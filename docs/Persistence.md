# Persistence

Explicit SQL, no ORM with change tracking, two supported providers, and schema evolution by
numbered migration scripts. Entity Framework is forbidden by the product's architecture rules
and by an automated test.

## Layout

```text
MailServer.Application/Abstractions/Persistence/    ports
MailServer.Infrastructure/Persistence/              provider-neutral machinery
MailServer.Persistence.Sqlite/                      dialect + factory + migrations
MailServer.Persistence.SqlServer/                   dialect + factory + migrations
```

The repositories are written **once**, in Infrastructure, against `ISqlDialect`. Only
genuinely divergent SQL is written twice, and `ISqlDialect` enumerates exactly which parts
those are — which makes the divergence auditable rather than scattered.

## Dapper, and where it stops

Dapper is a mapper over ADO.NET: no change tracking, no query translation, no hidden SQL. It
is used only inside `MailServer.Infrastructure/Persistence`. No handler, no domain type and no
Application abstraction mentions it, so replacing it would touch one folder.

Every query goes through `SqlRepositoryBase.Command(...)`, which is what guarantees the
transaction is always passed (a Dapper call that forgets it silently runs *outside* the
transaction) and that cancellation always flows (one that forgets it cannot be interrupted at
shutdown).

### Two type handlers you must know about

The providers return different CLR types for the same logical column:

| Column | SQL Server | SQLite |
|---|---|---|
| `DATETIMEOFFSET` / timestamp | `DateTimeOffset` | `string` (ISO-8601 TEXT) |
| `UNIQUEIDENTIFIER` / id | `Guid` | `string` |

`DapperConfiguration.Initialize()` registers handlers for both, and is called from
`AddInfrastructure` so no code path can reach a query with them unregistered. Without them
**nothing loads at all under SQLite** — every primary key in the schema is a GUID.

## Rows are not aggregates

Dapper materialises a flat `DomainRow`; `DomainRowMapper` converts it to `MailDomain`.

Letting Dapper populate the aggregate directly would require public settable properties on it,
which would destroy every invariant the aggregate exists to enforce — any caller could then
set `Status = Active` on a domain with no mail hostname.

The rehydration constructor performs **no** invariant checks beyond null guards. Data already
committed is by definition already valid, and re-validating on load would make a row written
by a newer version — or hand-edited during an incident — unloadable. Turning a small problem
into an unbootable service is not an improvement.

## Transactions

```csharp
public interface ITransactionManager
{
    Task<T> ExecuteScopedAsync<T>(Func<CancellationToken, Task<T>> action, CancellationToken ct);
}
```

| Rule | Reason |
|---|---|
| Commands get one transaction; queries get none | A read transaction costs a writer slot under SQLite for no benefit |
| Nested calls **join** the ambient transaction | A second write connection inside an open write transaction self-deadlocks under SQLite |
| The ambient session is **scoped DI**, not `AsyncLocal` | Rule 111 forbids static mutable state; an ambient static leaks across concurrent sessions |
| No `TransactionScope`, ever | It can silently promote to MSDTC; a mail server must not acquire a distributed-transaction dependency by accident |
| No network I/O inside a transaction | An SMTP conversation inside a transaction holds the SQLite writer for the remote server's response time |

### Retry safety

`TransactionManager` retries a transaction body up to three times on a transient error. This
is safe **only because** network I/O inside a transaction is forbidden: if a handler could
send an SMTP message inside its transaction, a retry would send it twice. That rule is what
makes the retry loop correct, which is why it is stated on the interface as well as the
implementation.

## Storing a message: two resources, no distributed transaction

The filesystem and the database cannot be committed atomically together. The ordering is:

```text
1. Write MIME to a temp file, flush, fsync, hash
2. Atomically move into its final content-addressed path
3. BEGIN TRANSACTION
4.   INSERT metadata referencing that path
5. COMMIT
6. Acknowledge to the SMTP peer (250)
```

A crash between 2 and 5 leaves an **orphaned blob** — recoverable, invisible to users, reaped
by housekeeping. The opposite ordering would leave a database row pointing at a nonexistent
file, which is user-visible data loss.

**We always fail toward an orphaned blob, never toward a dangling reference.** The peer is
acknowledged only after commit, so a crash before step 6 makes the sender retry — a duplicate,
which SMTP explicitly tolerates, and loss, which it does not.

## Migrations

Numbered SQL scripts shipped as **embedded resources**, so a deployment cannot be missing them
and an operator cannot edit an applied script on disk.

```text
MailServer.Persistence.Sqlite/Migrations/0001_InitialSchema.sql
MailServer.Persistence.SqlServer/Migrations/0001_InitialSchema.sql
```

### Directives

| Directive | Effect |
|---|---|
| `-- @Destructive` | Requires a backup first; refuses to run unattended until Milestone 13 delivers backups |
| `-- @NoTransaction` | Runs outside a transaction, for statements that cannot be transacted (`ALTER DATABASE`) |

Marking a script `@NoTransaction` is a visible decision, logged at Warning, because it gives
up atomicity.

### Guarantees, each with a test

1. **Never twice.** Applied versions are read first; only higher unapplied versions run.
2. **Transactional where supported.** SQL Server batches split on `GO`.
3. **Checksum drift is a hard error.** An edited applied script aborts startup with a message
   naming the script and the remedy. Line endings are normalised first — without that, a
   checkout with `core.autocrlf=true` would produce phantom drift on every developer machine.
4. **Fail safe.** A failure aborts startup. The service never runs against a partial schema.
5. **Advisory lock.** SQL Server uses `sp_getapplock` at session scope, so it spans several
   migration transactions. SQLite needs none: its single-writer file lock already serialises
   the whole run across processes.
6. **Unique, ordered versions.** Duplicates fail at startup, not at deploy time.

### Writing a migration

* Never edit an applied script. Add a new one.
* Keep both provider variants in step. Where they cannot be identical, say why in a comment
  rather than letting them drift silently.
* Prefer `RESTRICT` over `CASCADE` on anything referencing stored mail. Cascading a domain
  delete would remove mailbox rows while leaving every `.eml` file on disk unreferenced:
  unreclaimable storage and unrecoverable mail.
* Put `CHECK` constraints on state that has an invariant, even when the aggregate enforces it.
  The aggregate gives the good error message; the constraint is what holds under concurrency
  and against any future code path that bypasses the aggregate.

## Testing

`MailServer.Persistence.Tests` runs against **real, file-backed SQLite**, not in-memory.
In-memory SQLite behaves differently in exactly the ways these tests exist to check: WAL is
unavailable and the locking model differs. Testing persistence against a database that does
not behave like the production one proves nothing about production.

Covered: migrations, checksum drift, repository round-trips, unique-constraint mapping,
transaction commit and rollback, nested-transaction joining, eight concurrent writers, and a
reader proceeding while a write transaction is open.
