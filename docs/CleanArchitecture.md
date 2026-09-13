# Clean Architecture in AetherMail Server

## The rule

Dependencies point inward. Always. There are no exceptions and no "just this once".

```text
Hosts  →  Infrastructure  →  Application  →  Domain
```

`MailServer.Domain` is the innermost ring and references nothing but the base class library.

## How it is enforced

Layering that depends on reviewer discipline erodes, usually a week before a release. Three
mechanisms make a violation fail rather than merely look wrong.

### 1. The project file

`MailServer.Domain.csproj` declares **zero** `PackageReference` and **zero**
`ProjectReference` entries. Adding one is a one-line diff nobody can miss in review.

### 2. An architecture test

`MailServer.Domain.Tests/ArchitectureTests.cs` reflects over the compiled assembly and fails
the build if its referenced assemblies grow beyond an explicit allow-list of BCL assemblies.
This catches what the project file cannot: a *transitive* reference arriving through a
package.

It also asserts that no aggregate exposes a public setter, because a public setter lets any
caller bypass the method that enforces the invariant — setting `Status = Active` on a domain
with no mail hostname, for example.

### 3. The dependency graph itself

Some rules are structural rather than checked. `MailServer.Admin` does not reference either
persistence project, so `Microsoft.Data.Sqlite` and `Microsoft.Data.SqlClient` are absent
from the WPF application's dependency closure. It cannot open a database connection because
the types do not exist in its compilation. "No UI directly editing the database" is therefore
a compile-time guarantee rather than a convention.

## What belongs where

### Domain

Entities, aggregates, value objects, enums, domain events, domain exceptions, pure policies.

The test is simple: **could this rule be explained to a mail administrator without mentioning
software?** "A domain cannot be enabled without a mail hostname, because mail from a domain
with no outbound identity fails SPF, DKIM alignment and reverse-DNS checks at every major
receiver" is a domain rule. "Retry after 1, 5, 15, 30 minutes" is a domain rule. "Open a
transaction" is not.

Nothing in this layer knows that SQL, sockets, DNS, WPF or ASP.NET Core exist.

### Application

Use cases and the **ports** the outer layers implement.

A command handler orchestrates: load the aggregate, tell it to do something, save it. It does
not contain the rule — the aggregate does. When you find yourself re-checking in a handler
something the aggregate already enforces, delete the handler's copy. A rule implemented in
two places will eventually disagree with itself, and the copy the user sees is the wrong one
to trust.

Ports are named for what the Application needs, not for what implements them:
`IMessageStore`, not `IFileSystemMessageStore`. That is what makes the ACME provider, the
DNS challenge provider, the malware scanner and the reputation provider swappable without
touching a use case.

### Infrastructure

Implementations. Dapper, connection factories, the migration runner, DPAPI, Serilog wiring,
the filesystem message store.

Provider-*specific* packages do not live here — they live in the leaf persistence projects.
Infrastructure holds the provider-*neutral* machinery, including the repositories, which are
written once against `ISqlDialect` rather than twice per provider. Two hand-maintained copies
of the same SQL is where drift breeds, and drift in a mail store means bugs that appear on
only one provider and are therefore found in production.

### Hosts

Composition roots. `MailServer.Service` is the mail server. `MailServer.Admin` is a
management console. `MailServer.WebEndpoints` is a library hosted *inside* the service, not a
second process — one process, one configuration, one certificate provider, one thing to
install and secure.

## Where the rule bends, and why it does not break

**Protocol code does not go through MediatR.** Allocating a request object and walking eight
pipeline behaviors for every `RCPT TO`, on a server handling hundreds of concurrent sessions,
is unjustifiable overhead. The SMTP state machine also needs synchronous, ordered,
per-connection decisions rather than a mediator.

So SMTP and IMAP depend on narrow Application services — `IRelayPolicy`,
`IInboundMailPipeline`, `ISmtpAuthenticator` — which are themselves Application abstractions.
The business logic still lives in the Application layer; only the dispatch mechanism differs.
The rule "no business logic in protocol socket handlers" holds; the mediator tax does not
apply to the hot path.

**`System.Data.Common` appears in the Application layer.** `ITransactionManager` exposes
`DbConnection` and `DbTransaction`. These are provider-neutral BCL abstractions, not a
persistence technology: nothing above the persistence projects ever names `SqliteConnection`
or `SqlConnection`. The alternative — inventing a parallel connection abstraction — would add
a layer of indirection that buys nothing.

## Reading the code in dependency order

1. `src/MailServer.Domain/ValueObjects/DomainName.cs` — why two representations, and what
   "never silently corrupt addresses" costs
2. `src/MailServer.Domain/Entities/MailDomain.cs` — an aggregate that refuses invalid
   transitions, with the reasoning on each one
3. `src/MailServer.Application/Abstractions/` — the ports, which are the real contract
4. `src/MailServer.Application/Behaviors/` — the pipeline, in order
5. `src/MailServer.Infrastructure/Persistence/` — how the ports are satisfied
6. `src/MailServer.Service/Program.cs` — the composition root, where it all meets
