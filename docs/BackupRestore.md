# Backup and Restore

> **Status: Planned — Milestone 13.** This documents the design and, importantly, the trap
> that must be designed around from the start.

## What must be backed up

| Item | Why |
|---|---|
| Database | Domains, mailboxes, queue state, audit trail, metadata |
| Message store | The actual mail. The database holds only references |
| Configuration | `appsettings.machine.json` under ProgramData |
| **DKIM private keys** | Losing these breaks every signature until new keys propagate |
| **ACME account key** | Losing it forfeits the ability to revoke issued certificates |
| Certificates and passphrases | |
| **Secret entropy file** | Without it, every DPAPI-protected secret above is unrecoverable |
| Policies and IP rules | |

## The DPAPI trap — read this before you need it

**DPAPI is machine-scoped. A backup restored onto a different machine cannot decrypt any of
the secrets above.**

This is not a bug and cannot be worked around at restore time. It is a consequence of the
protection that makes a stolen database useless, and it is exactly the kind of thing that is
discovered during a disaster if it is not designed for beforehand.

Therefore: **backups re-wrap secrets under a passphrase-derived key at export time.**

```text
Export:   DPAPI-unprotect  →  re-wrap under a key derived from the operator's passphrase
Restore:  passphrase  →  derive  →  unwrap  →  DPAPI-protect for the NEW machine
```

The passphrase is set when the backup is configured and is **not stored anywhere by the
product**. Losing it means losing the DKIM and ACME keys, exactly as intended — but it must be
recorded somewhere the operator will still have access to when the server is gone.

Restore-to-a-new-machine is an exercised procedure with its own test, not a theory.

## Database backups

**SQL Server** — use its own mechanism:

```sql
BACKUP DATABASE [AetherMail] TO DISK = '...' WITH CHECKSUM, COMPRESSION, INIT;
RESTORE VERIFYONLY FROM DISK = '...' WITH CHECKSUM;
```

Copying MDF/LDF files is explicitly rejected. Copying an attached database produces a file
that is torn at best and silently corrupt at worst — and the corruption is typically
discovered during the restore that was supposed to save you.

**SQLite** — checkpoint first, then copy. WAL mode means recent transactions live in
`mailserver.db-wal`, so copying only the `.db` file produces a backup that silently loses
them. Either use SQLite's backup API or checkpoint and copy all three files together.

## Ordering matters

```text
1. Enter a maintenance mode that stops administrative writes
2. Back up the message store    ← FIRST
3. Back up the database          ← SECOND
4. Back up secrets and configuration
5. Return to normal
```

The store is backed up **before** the database on purpose. If the store is slightly ahead of
the database at restore, the surplus files are orphans: invisible to users and reaped by
housekeeping. If the database were ahead, rows would point at files that do not exist — which
is user-visible data loss.

**We always fail toward orphaned blobs, never toward dangling references.** This is the same
principle that governs message ingestion; see `docs/Persistence.md`.

## Verification

A backup that has never been restored is a hypothesis, not a backup.

The product verifies checksums, confirms the database restores to a scratch location, and
confirms a sample of message files is readable and hashes correctly. The verification result
is a health check, so a silently failing backup shows on the dashboard rather than in a log
nobody reads.

## Retention

Configurable, with a floor. Keeping one backup means a corruption discovered on Tuesday has
already overwritten Monday's good copy.

## Restore

1. Install the same product version. Restoring into a *newer* schema is supported; restoring
   into an *older* one is not.
2. Restore the database.
3. Restore the message store.
4. Restore secrets using the backup passphrase — they are re-protected for the new machine.
5. Verify: schema version, message count against metadata count, certificate validity, DKIM
   keys matching what DNS publishes.
6. Start the service, which migrates if the build is newer.
7. Run the deliverability check before resuming mail flow. A restored server with stale DKIM
   keys will fail authentication everywhere until DNS agrees again.
