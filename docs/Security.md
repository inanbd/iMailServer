# Security

## Threat model

A public mail server is one of the most exposed services an organisation runs. It accepts
unauthenticated connections from the entire Internet by design, handles hostile content as its
normal workload, and holds every message the organisation has ever received.

| Threat | Mitigation | Milestone |
|---|---|---|
| Open relay | Deny-by-default relay policy; automated tests across every listener role and auth state | 6 |
| Credential theft | Argon2id hashing; AUTH only over TLS; never logged; constant-time comparison | 2, 7 |
| Brute force / credential stuffing | Per-IP and per-account throttling with exponential lockout; generic failure messages | 2, 7 |
| STARTTLS command injection | Full session-state reset after the handshake, with a dedicated test | 6 |
| SQL injection | Parameterised SQL exclusively; the one un-parameterisable thing (ORDER BY) comes from a closed enum | **1** |
| Path traversal | Server-generated identifiers only; containment check as defence in depth | **1** |
| Resource exhaustion | Bounded reads, timeouts, per-command limits, streaming, MIME depth caps | **1** (framing), 6 |
| IPC privilege escalation | ACL-restricted pipe; explicit command allow-list; per-command permissions | **1** |
| Secret disclosure | DPAPI-protected store; ACLs; hand-written audit descriptors | **1** |
| Malicious content | Layered pipeline; quarantine; `IMalwareScanner` delegating to a real engine | 12 |
| Becoming a spam source | Per-mailbox limits; outbound anomaly detection; no evasion features | 12 |
| Supply chain | Central package management, pinned versions, nuget.org only | **1** |

Items marked **1** are implemented and tested now.

---

## What is enforced today

### The administration UI cannot reach the database

`MailServer.Admin` does not reference either persistence project. `Microsoft.Data.Sqlite` and
`Microsoft.Data.SqlClient` are absent from its dependency closure, so it cannot open a
database connection — the types do not exist in its compilation. Rule 105's "No UI directly
editing database" is a compile-time guarantee, not a convention.

### The IPC command registry is an allow-list

The obvious implementation — accept an assembly-qualified type name and call `Type.GetType` —
would hand anyone who can reach the pipe the ability to instantiate arbitrary types inside the
service process. That is a remote code execution primitive, traded away for the convenience of
not writing a dictionary.

Instead, wire names map to types through a hand-written table. A request type that is not in
that table is unreachable from outside the process, whatever the caller sends.

The registry's constructor additionally **refuses to build** if a registered command does not
declare a required permission, so "forgot to add authorization" fails the service's first
second of life rather than shipping as an unauthenticated administrative endpoint. Tests assert
both properties, including that an assembly-qualified type name is simply an unknown command.

### The pipe is ACL-restricted

Created with `NamedPipeServerStreamAcl.Create`, granting the local Administrators group and
the service account, and **explicitly denying `NETWORK`**. A named pipe created with default
security is reachable by every authenticated user on the machine, and this one carries domain
creation, mailbox management and certificate operations.

On non-Windows platforms .NET implements named pipes over Unix domain sockets where
`PipeSecurity` does not exist. The pipe is then created without an ACL and a warning is logged
on **every** creation. Development only, and never silent.

The client connects with `TokenImpersonationLevel.Identification` — the service needs to know
who is calling; it must never be able to act as them.

### The frame length prefix is validated before any allocation

The prefix is attacker-influenced data read before any buffer exists. Reading it and calling
`new byte[length]` is how a four-byte message becomes a two-gigabyte allocation and takes the
mail server down.

It is checked against both a configured maximum and an absolute ceiling that no configuration
can raise, plus rejection of negative and zero lengths. Tested.

### Identity fails closed

The scoped `MutableAdminContext` starts **unauthenticated with no permissions**. If the IPC
layer ever fails to call `Assign` — a bug, a new code path, a refactor — the authorization
behavior denies every request rather than granting them. The failure mode of forgetting to
authenticate is "nothing works", not "everything is permitted". Tested.

Read and write are separate interfaces over the same instance: handlers get the read-only
`IAdminContext`, and only the authentication boundary resolves `IAdminContextInitializer`. One
read-write interface would let any handler quietly promote its own permissions.

### Authorization precedes validation

An information-disclosure defence. If validation ran first, an unauthorized caller could read
the errors as an oracle: "domain 'secret-client.com' already exists" tells them something they
are not entitled to know. Asserted by `PipelineOrderTests`.

### Secrets never reach logs or the audit trail

Neither the logging behavior nor the audit behavior serialises the request object. Both use
the hand-written `AuditDescriptor`. Adding a secret-bearing field to a command therefore
cannot start leaking it: the field is invisible until somebody deliberately adds it to the
descriptor.

Never logged, anywhere: passwords, AUTH credentials, ACME account keys, DKIM private keys,
certificate private keys and passphrases, recovery keys, smarthost credentials.

### There is no insecure fallback

`DevelopmentSecretProtector` exists so the server can be developed on a non-Windows machine.
It is never selected automatically. It requires explicit configuration, the options validator
**refuses** it when the environment is Production, it reports `IsProductionGrade == false`, and
it logs a **Critical** warning on every start.

Similarly, if DPAPI is configured on a non-Windows machine the service refuses to start with
an explanation rather than quietly substituting the development protector. Satisfying rule 105
in letter while violating it in spirit is not an option.

### Path containment

Every stored path is built from server-generated ULIDs. No component — not the sender, not the
subject, not a client-supplied filename — is ever derived from user input, so traversal is
impossible by construction.

A containment check still runs on every resolution and throws loudly on violation. Reaching it
means a bug in path construction rather than hostile input, which is exactly why it must be
loud rather than silently sanitised. Tested, including the sibling-prefix case
(`…/Messages-evil` versus `…/Messages`), which only the trailing separator distinguishes.

---

## Secret protection

`ISecretProtector` wraps DPAPI at `LocalMachine` scope with additional entropy held in an
ACL-protected file.

**Why machine scope.** The service runs under a dedicated account and must read DKIM and ACME
keys at boot with nobody logged in. User scope would tie them to a profile that is not loaded.

**Why additional entropy.** Machine-scope DPAPI alone means any process on the machine can
unprotect the data. The entropy file adds a second factor under an ACL granting only the
service account and administrators, so a copied database is not sufficient to recover DKIM
private keys.

**The backup consequence.** DPAPI is machine-scoped: a backup restored onto a new machine
cannot decrypt these secrets. Backups therefore re-wrap secrets under a passphrase-derived key
at export time. This is an exercised, documented procedure — see `docs/BackupRestore.md` — not
a surprise discovered during a disaster.

The entropy file is never regenerated on mismatch. Doing so would render every existing
protected secret unrecoverable, so a corrupt file refuses startup with an explanation instead.

---

## Passwords (Milestone 2)

Argon2id, via `Konscious.Security.Cryptography.Argon2`. The BCL has no Argon2, and PBKDF2 is
materially weaker against GPU attack.

Stored separately from the mailbox record: hash, salt, algorithm, work factor, created
timestamp. Never encrypted for reversible storage — anything that goes through
`ISecretProtector` is something the server must read back, and a password is not.

Validation is constant-time. Failures produce a generic message regardless of whether the
account exists, because a distinguishable "no such user" is a username-enumeration oracle.

---

## Reporting a vulnerability

Do not open a public issue. Contact the maintainers privately with reproduction steps and a
window for a fix before disclosure.
