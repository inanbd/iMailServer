# Microsoft SQL Server Provider

The recommended provider for production. That recommendation appears in the setup wizard, the
health report and the deliverability readiness score, not only here.

## Connection security

`Encrypt=True` is forced on. `TrustServerCertificate` is **off** by default and, if an
operator turns it on, the factory logs a warning naming the actual risk:

> The link is encrypted but the server's identity is NOT verified, so it is vulnerable to an
> active man-in-the-middle.

Rule 105's prohibition on certificate-validation bypass includes the database link. An
unvalidated connection carries every mailbox row and every audit record.

### Credentials

Integrated Security under the service account is preferred. For SQL authentication, the
connection string lives in the DPAPI-protected secret store and configuration holds only
`ConnectionStringSecretName`. The options validator **refuses to start** in a Production
environment if an inline connection string is present — a credential in a JSON file ends up
in support tickets and source control.

`DescribeTarget()` returns only the server and database, built from the parsed builder, so a
credential cannot leak through a string that happened to be formatted unexpectedly.

## Isolation

`0001_InitialSchema.sql` sets `READ_COMMITTED_SNAPSHOT ON`.

This gives SQL Server the same reader/writer independence that WAL gives SQLite: a dashboard
query or an IMAP fetch never blocks behind the queue processor's writes. Without it the two
providers would have materially different concurrency behaviour, and code correct on one would
deadlock on the other.

`ALTER DATABASE` cannot run inside a user transaction, which is why that script is marked
`-- @NoTransaction`. It is idempotent and makes no schema change, so re-running it after a
failure is safe.

## Transient error handling

`SqlServerDialect.IsTransient` classifies the documented transient conditions: deadlock victim
(1205), lock request timeout (1222), Azure SQL throttling (49918, 40501, 40197, 10928, 10929),
connection-establishment failures, and the in-memory OLTP validation failures.

Getting this wrong costs in both directions. Retrying a constraint violation loops forever
while looking like a hang; failing a deadlock victim aborts work that would have succeeded on
a second attempt.

`ConnectRetryCount` is set so that a SQL Server restart or an Azure SQL failover produces a
brief pause rather than a cascade of failures.

## Indexing strategy

Primary keys are `NONCLUSTERED`; the clustered index is placed where reads actually go.

| Table | Clustered on | Why |
|---|---|---|
| `Domains` | `Name` (unique) | Every inbound `RCPT TO` resolves its recipient domain here. Clustering on a GUID would scatter inserts across the B-tree for no read benefit |
| `Mailboxes` | `Address` (unique) | Resolved on every `RCPT TO` and every login |
| `AuditRecords` | `TimestampUtc DESC` | Append-only and almost always read newest-first, so writes stay sequential and range scans stay cheap |

Nonclustered indexes use `INCLUDE` so the hot queries are served entirely from the index
without lookups into the base table.

GUID keys are generated with `Guid.CreateVersion7()` — time-ordered, so clustered inserts stay
sequential instead of fragmenting the way random v4 GUIDs do. That single choice is worth a
great deal of write throughput on the queue and message tables.

## The queue pattern (Milestone 8)

```sql
UPDATE TOP (@batch) q WITH (READPAST, UPDLOCK, ROWLOCK)
SET    Status = 1, LeaseOwner = @owner, LeaseExpiresUtc = @expires
OUTPUT inserted.*
FROM   OutboundQueue q
WHERE  q.Status = 0 AND q.NextAttemptUtc <= SYSUTCDATETIME();
```

`READPAST` is what makes this work at scale: multiple workers skip each other's locked rows
instead of blocking. Combined with the lease columns, a crashed worker's items are reclaimed
when the lease expires rather than stranding as `Processing` forever.

A filtered index on the hot predicate keeps the scan small:

```sql
CREATE NONCLUSTERED INDEX IX_OutboundQueue_Ready
    ON OutboundQueue (NextAttemptUtc)
    INCLUDE (DestinationDomain, Priority)
    WHERE Status IN (0, 2);
```

## Backups

Use SQL Server's own mechanism:

```sql
BACKUP DATABASE [AetherMail]
    TO DISK = 'D:\Backups\AetherMail.bak'
    WITH CHECKSUM, COMPRESSION, INIT;

RESTORE VERIFYONLY FROM DISK = 'D:\Backups\AetherMail.bak' WITH CHECKSUM;
```

**Copying MDF/LDF files is explicitly rejected.** Copying an attached database produces a file
that is torn at best and silently corrupt at worst, and the corruption is typically discovered
during the restore that was supposed to save you.

The mail store on disk must be backed up in the same window as the database. A database
restored to a point where the filesystem is ahead leaves rows pointing at files that have not
been written yet — see `docs/BackupRestore.md`.

## Permissions

The service account needs `db_datareader`, `db_datawriter`, `EXECUTE`, and — for migrations —
`db_ddladmin`. It does **not** need `sysadmin` or `db_owner`.

`sp_getapplock` and `sp_releaseapplock` require `public`, which is granted by default.

## Sizing

There is no useful universal answer, but as a starting point: the message *store* is on the
filesystem, not in the database, so the database grows with metadata, queue history, delivery
attempts and reports rather than with mail volume. Delivery-attempt rows are the fastest
growing table on a busy server, and their retention is the first thing to tune.
