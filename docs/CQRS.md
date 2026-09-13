# CQRS and the MediatR Pipeline

## Commands and queries

Every administrative operation is a command; every read is a query. They are distinguished
by marker interfaces rather than by a naming convention, so the pipeline can make decisions
from the type system instead of from a string suffix.

```csharp
public interface ICommand<out TResponse> : IRequest<TResponse>;
public interface IQuery<out TResponse>   : IRequest<TResponse>;
```

Four further markers opt a request into pipeline behaviour:

| Marker | Effect |
|---|---|
| `ITransactionalRequest` | The handler runs inside one database transaction |
| `IAuditableRequest` | An audit record is written, from a descriptor the request writes by hand |
| `IAuthorizedRequest` | The declared permission is enforced before anything else happens |

## Two read paths, deliberately

**Repositories** load and persist aggregates. They return domain objects, participate in
transactions, and are used by commands.

**Query services** serve read models: hand-tuned SQL returning flat DTOs shaped for a
specific screen, with filtering, sorting and paging pushed into the database.

Forcing a 10 000-row queue grid through aggregate rehydration would be slow and would build
objects nobody needs. Forcing a state transition through a flat DTO would bypass every
invariant. Keeping both, and being explicit about which is which, is the whole point.

## The pipeline

Eight behaviors, outermost first. **The order is load-bearing** and is asserted by
`PipelineOrderTests`, so an edit that reorders the registrations fails the build.

```text
1. Correlation        assign/flow the correlation id
2. UnhandledException log the failure; flush deferred audit records
3. Performance        stopwatch; warn over threshold
4. Logging            structured begin/end — never serialises the request
5. Authorization      enforce IAuthorizedRequest; enforce maintenance mode
6. Validation         FluentValidation, all failures aggregated
7. Transaction        one transaction per ITransactionalRequest
8. Audit              write the audit record inside that transaction
        ↓
     Handler
```

### Why this order

**Correlation first.** Everything below it, including the exception logger, needs an id to
attach. Assigning it later leaves the earliest and most interesting failures uncorrelated,
which is exactly when correlation matters most.

**Exception handling second.** Sitting outside validation, authorization and the transaction
means it catches failures thrown *by* those stages too, not only by the handler — and its
`finally` runs after the transaction has rolled back, which is what makes the deferred audit
flush safe.

**Authorization before validation.** This is an information-disclosure defence, not
tidiness. If validation ran first, an unauthorized caller could read the errors as an oracle:
"domain 'secret-client.com' already exists" tells them something they are not entitled to
know. Denying first means an unauthorized caller learns exactly one thing — that they are
unauthorized.

**Validation before the transaction.** A malformed request must never open a database
transaction. Under SQLite, write transactions serialise; opening one only to roll it back
because a field was empty steals a writer slot from the queue processor.

**Audit inside the transaction.** The audit record for a successful change commits with the
change, or not at all. An audit trail that can disagree with the data it describes is worse
than no audit trail, because it is trusted.

## Auditing without leaking secrets

The audit behavior does **not** reflect over the request object. It calls
`IAuditableRequest.DescribeForAudit()` and stores only what comes back.

```csharp
public AuditDescriptor DescribeForAudit() =>
    new("Domain.Create", nameof(MailDomain), Name);
```

The reason is concrete. A generic "serialise the request and store it" audit behavior would
faithfully write a new mailbox password, an imported PFX passphrase or a smarthost credential
into the audit table the moment somebody added such a field to a command. Because the
descriptor is hand-written, a newly added secret-bearing field is **absent** from the audit
trail until a developer deliberately puts it there.

`LoggingBehavior` follows the same discipline for the same reason: log files end up in
support tickets.

## The two audit write paths

Successes are written immediately, joining the ambient transaction. Failures and denials are
**deferred**: queued during the request and flushed from a separate connection once the
failed transaction has rolled back.

Writing a failure immediately would roll it back along with the transaction that failed — the
record of the failure would vanish with the failure itself. Flushing it while the write
transaction is still open would open a second write connection, which under SQLite's
single-writer model deadlocks against the transaction being rolled back. Hence: queue, unwind,
then flush.

## Where MediatR stops

MediatR handles administrative use cases and coarse-grained operations. It is **not** used
per-SMTP-verb or per-IMAP-command — see `docs/CleanArchitecture.md` for why.

## Adding a use case

1. Define the command or query as a `record` implementing the relevant markers.
2. Write the handler as an `internal sealed class`. Orchestrate; do not re-implement rules the
   aggregate owns.
3. Write a `FluentValidation` validator. Delegate to the value objects' `TryParse` rather than
   re-implementing a grammar with a regular expression.
4. Register it in `IpcCommandRegistry` if the admin application needs it. The registry's
   constructor **refuses** a command that does not declare a required permission, so "forgot
   to add authorization" fails the service's first second of life.
5. Add handler tests that construct the handler directly with fakes. Testing through the full
   pipeline tests the pipeline as much as the handler and makes failures harder to localise.

## A note on MediatR

Pinned to **12.5.0** — the last Apache-2.0 release. Versions 13 and later ship under a
commercial licence. Handlers depend only on `IRequestHandler` and hosts only on `ISender`,
both trivially replaceable; a roughly 150-line in-house dispatcher could take over in a day.
This is risk 1 in `docs/Architecture.md` §28 and wants a decision before Milestone 5.
