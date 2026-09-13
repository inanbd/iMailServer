# SQLite Provider

SQLite is a first-class supported provider — for development, testing, appliance installs and
small deployments. It is not a toy mode. Its concurrency model, however, dictates specific
design choices that do not apply to SQL Server.

## When to use it

**Suitable for:** development and testing, personal servers, small businesses, roughly up to a
few dozen mailboxes and modest sustained volume.

**Move to SQL Server when:** mailbox counts reach the low hundreds, sustained delivery volume
grows, several queue workers are needed, or the backup and restore window matters
operationally.

The admin UI states this plainly rather than letting an installation quietly outgrow its
database, and the SQLite → SQL Server migration tool arrives in Milestone 13.

## Connection settings, and why each one matters

Applied **per connection** by `SqliteConnectionFactory`, because pooling hands back
connections that do not remember session state.

| Pragma | Value | Why |
|---|---|---|
| `journal_mode` | `WAL` | The default rollback journal makes readers and the writer block each other. Under WAL an IMAP client reads while the queue writes — the normal state of a working mail server |
| `synchronous` | `NORMAL` | Durable across a process crash under WAL, and far cheaper per queue update than `FULL` |
| `busy_timeout` | 5000 ms | Without it, hitting the writer lock fails instantly with `SQLITE_BUSY` instead of waiting the moment the writer needs |
| `foreign_keys` | `ON` | **Off by default in SQLite, per connection.** A server that assumes referential integrity while the engine is not enforcing it accumulates orphaned rows silently |
| `cache_size` | negative KiB | Bounded memory rather than a page count |
| `temp_store` | `MEMORY` | Keeps sort and index scratch off the mail volume |

Pragma values cannot be parameterised, so each is validated against a closed allow-list before
interpolation. Configuration is trusted, but "trusted input interpolated into SQL" is a habit
worth never forming.

Shared cache is deliberately **not** used: it is a documented source of hard-to-diagnose
table-level locking errors, and WAL gives better concurrency without it.

## The write gate

SQLite permits exactly one writer. Several queue workers, the IMAP `APPEND` path and the admin
console all competing for that slot produce `SQLITE_BUSY` storms, because each contender burns
its busy-timeout budget before failing.

`SqlWriteGate` — an `AsyncSemaphore` of one — admits write transactions one at a time. That
converts contention into an orderly queue: waiters are admitted in turn, nobody times out, and
throughput actually *improves* because no work is wasted on retries. Reads are untouched and
run fully concurrently thanks to WAL.

The gate is enabled from `ISqlDialect.RequiresSerializedWrites`, so it is a no-op under SQL
Server, where the engine handles concurrent writers properly and serialising them in-process
would discard most of its throughput. This is the one place a provider difference leaks
upward, and it leaks as a capability flag rather than as a type check.

### Consequences for handler code

* Keep write transactions short.
* Never make a network call inside one. "Open transaction → SMTP delivery → commit" is
  forbidden; delivery happens outside and the result is recorded in a second short transaction.
* Never open a second connection inside a transaction. `ITransactionManager` joins the ambient
  one rather than nesting, precisely because nesting would self-deadlock.

## Storage format

| CLR type | Stored as | Read back as |
|---|---|---|
| `Guid` | TEXT, 36-character "D" form | `string` — handled by `DapperConfiguration` |
| `DateTimeOffset` | TEXT, ISO-8601 with offset | `string` — handled by `DapperConfiguration` |
| `bool` | INTEGER 0/1 | `long` |
| enums | INTEGER, matching the Domain layer's pinned values | `long` |

TEXT for GUIDs keeps the data legible to the `sqlite3` CLI for support and forensics, and
SQLite has no fixed-width binary advantage to give up.

## Files on disk

WAL mode creates two companions beside the database:

```text
mailserver.db        the database
mailserver.db-wal    the write-ahead log
mailserver.db-shm    shared-memory index
```

**A backup must include all three, or be taken from a checkpointed database.** Copying only
the `.db` file while the WAL holds recent transactions produces a backup that silently loses
them — see `docs/BackupRestore.md`.

## Verifying it is actually working

Two things fail silently if a pragma does not apply, so both are asserted by tests
(`MigrationRunnerTests`) and are worth checking by hand after an upgrade:

```sql
PRAGMA journal_mode;   -- must be: wal
PRAGMA foreign_keys;   -- must be: 1
```

A server that thinks it has WAL but does not will pass every single-threaded test and fall
over under concurrency in production.

## Troubleshooting

**`SQLITE_BUSY` under load.** The write gate should prevent this in-process. If it appears,
something is writing outside the gate — a second process, or a code path opening its own
connection instead of going through `ITransactionManager`.

**The database file grows and does not shrink.** WAL checkpoints on a schedule; deleting rows
does not return space to the filesystem without `VACUUM`. Housekeeping handles this from
Milestone 13.

**"Database is locked" at startup.** Another instance of the service is running, or a
`sqlite3` session has the file open with a transaction pending.
