# AetherMail Server — Architecture Decision Record

**Status:** Baseline architecture, agreed before Milestone 1 implementation.
**Target platform:** Windows Server 2019 / 2022 / 2025, x64.
**Runtime:** .NET 10, C# 14.
**Document owner:** Principal architect.

This document answers the thirty design questions required before any production code is
written. It is the contract that every subsequent milestone is measured against. Where a
decision is deliberately deferred, the milestone that closes it is named.

---

## 0. Reading guide

| Section | Question answered |
|---|---|
| 1 | Clean Architecture diagram |
| 2 | Project dependency diagram |
| 3 | CQRS / MediatR architecture |
| 4 | Windows Service architecture |
| 5 | WPF administration architecture |
| 6 | SMTP architecture |
| 7 | IMAP architecture |
| 8 | Outbound queue architecture |
| 9 | SQLite architecture |
| 10 | SQL Server architecture |
| 11 | SQL migration strategy |
| 12 | Transaction strategy |
| 13 | Message storage architecture |
| 14 | Certificate architecture |
| 15 | Let's Encrypt / ACME lifecycle |
| 16 | Self-signed certificate strategy |
| 17 | Windows Certificate Store strategy |
| 18 | DNS architecture |
| 19 | DKIM / SPF / DMARC architecture |
| 20 | Deliverability architecture |
| 21 | Security architecture |
| 22 | Recommended NuGet packages with justification |
| 23 | Domain entity list |
| 24 | Repository / query abstractions |
| 25 | Directory structure |
| 26 | Configuration model |
| 27 | Development milestones |
| 28 | Major risks |
| 29 | Difficult protocol areas |
| 30 | Recommended changes before development starts |

---

## 1. Clean Architecture diagram

Dependencies point **inward only**. The Domain layer is the innermost ring and references
nothing but the BCL. Nothing in the diagram below ever points outward.

```text
                        ┌──────────────────────────────────────────────┐
                        │                  HOSTS                       │
                        │  (composition roots — wire everything up)    │
                        │                                              │
                        │   MailServer.Service    MailServer.Admin     │
                        │   (Windows Service)     (WPF, MVVM)          │
                        │   MailServer.WebEndpoints                    │
                        │   (Kestrel: ACME, MTA-STS, health, unsub)    │
                        └───────────────────┬──────────────────────────┘
                                            │ depends on
                                            ▼
     ┌───────────────────────────────────────────────────────────────────────┐
     │                    INFRASTRUCTURE / ADAPTERS                          │
     │  (implements Application abstractions with concrete technology)       │
     │                                                                       │
     │  MailServer.Infrastructure          MailServer.Persistence.Sqlite     │
     │  MailServer.Ipc                     MailServer.Persistence.SqlServer  │
     │  MailServer.Protocols.Common        MailServer.Protocols.Smtp         │
     │  MailServer.Protocols.Imap          MailServer.Protocols.Pop3         │
     │  MailServer.Deliverability          MailServer.Filtering              │
     └───────────────────────────────────┬───────────────────────────────────┘
                                         │ depends on
                                         ▼
     ┌───────────────────────────────────────────────────────────────────────┐
     │                          APPLICATION                                  │
     │  Use cases. Knows *what* the system does, never *how* it is stored,   │
     │  transported, rendered or encrypted.                                  │
     │                                                                       │
     │  Commands · Queries · Handlers · Validators · Pipeline Behaviors       │
     │  DTOs · Policies · Authorization requirements                         │
     │  Abstractions (ports): IDomainRepository, ITransactionManager,        │
     │  IMessageStore, ICertificateManager, IDnsResolver, IClock, …          │
     └───────────────────────────────────┬───────────────────────────────────┘
                                         │ depends on
                                         ▼
     ┌───────────────────────────────────────────────────────────────────────┐
     │                            DOMAIN                                     │
     │  Entities · Aggregates · Value Objects · Enums · Domain Events        │
     │  Domain Exceptions · Invariants · Pure Policies                       │
     │                                                                       │
     │  References: BCL only. No SQL, no sockets, no DNS, no WPF, no ASP.NET │
     └───────────────────────────────────────────────────────────────────────┘
```

### Enforcement, not convention

Layering is enforced mechanically, not by reviewer discipline:

* `MailServer.Domain.csproj` sets `<EnableDefaultItems>` normally but declares **zero**
  `PackageReference` entries other than analyzers. Any attempt to add Dapper, SqlClient or
  WPF to it is visible in a one-line diff.
* A dedicated architecture test (`MailServer.Domain.Tests/ArchitectureTests.cs`) reflects
  over the loaded assemblies and fails the build if `MailServer.Domain` references any
  assembly outside an allow-list, or if `MailServer.Application` references a persistence
  or protocol assembly.
* `Directory.Build.props` sets `TreatWarningsAsErrors` and enables nullable reference
  types solution-wide.

### What "Application must not know how" means in practice

The Application layer defines `IMessageStore.WriteAsync(...)` and never learns whether the
bytes landed on NTFS, a UNC share, or (later) object storage. It defines
`ICertificateManager.RequestAcmeCertificateAsync(...)` and never learns that Certes is
underneath. This is what makes the ACME provider, the DNS challenge provider, the malware
scanner and the reputation provider swappable without touching a use case.

---

## 2. Project dependency diagram

```text
                                MailServer.Domain
                                        ▲
                                        │
                                MailServer.Application
                                        ▲
              ┌─────────────┬───────────┼────────────┬──────────────┬───────────────┐
              │             │           │            │              │               │
   MailServer.Infrastructure│  MailServer.Ipc   MailServer.       MailServer.   MailServer.
              ▲             │           ▲       Protocols.Common  Deliverability  Filtering
              │             │           │            ▲                  ▲             ▲
   ┌──────────┴──────────┐  │           │      ┌─────┴──────┬──────────┐│             │
   │                     │  │           │      │            │          ││             │
MailServer.        MailServer.          │  Protocols.   Protocols.  Protocols.        │
Persistence.       Persistence.         │    Smtp         Imap        Pop3            │
Sqlite             SqlServer            │      ▲            ▲          ▲              │
   ▲                     ▲              │      │            │          │              │
   └──────────┬──────────┘              │      └────────────┴──────────┴──────────────┘
              │                         │                    │
              └─────────────┬───────────┴────────────────────┘
                            │
              ┌─────────────┴──────────────┬──────────────────────┐
              │                            │                      │
     MailServer.Service           MailServer.Admin      MailServer.WebEndpoints
     (Windows Service host)       (WPF; references      (Kestrel; referenced by
                                   Ipc + Application     MailServer.Service, not
                                   DTOs only — never     a standalone process)
                                   Persistence)
```

### Hard rules encoded in this graph

1. **`MailServer.Admin` never references a persistence project.** The WPF application
   physically cannot open a database connection, because `Microsoft.Data.Sqlite` and
   `Microsoft.Data.SqlClient` are not in its dependency closure. Rule 105 ("No UI directly
   editing database") is therefore a compile-time guarantee rather than a code-review note.
2. **`MailServer.Admin` references `MailServer.Application` for DTOs and contract types
   only.** It does not reference `MailServer.Infrastructure`, so it cannot resolve a
   handler. Every operation travels over IPC.
3. **Persistence providers are leaves.** Nothing references
   `MailServer.Persistence.Sqlite` except the composition root, which selects it at runtime
   from configuration. Swapping providers touches exactly one `if`.
4. **`MailServer.WebEndpoints` is a library, not an executable.** ASP.NET Core / Kestrel is
   hosted *inside* the Windows Service so that ACME challenges, MTA-STS policy serving and
   health endpoints share one process, one configuration and one certificate store. There
   is no second service to install, secure or keep running.
5. **`MailServer.Protocols.Common` holds no protocol grammar.** It holds transport
   primitives: bounded line readers, TLS negotiation helpers, session transcript recorders,
   connection accounting. SMTP, IMAP and POP3 grammars live in their own projects.

### Why `MailServer.Ipc` exists as its own project

The IPC contract is shared by two processes that must be able to version independently
(an upgraded service and a not-yet-upgraded admin app can coexist during an upgrade
window). Putting the wire contract in its own assembly with an explicit protocol version
constant makes that compatibility surface visible and testable.

---

## 3. CQRS / MediatR architecture

### Shape

Every administrative operation is a `Command`; every read is a `Query`. Both flow through
one MediatR pipeline. Protocol code (SMTP, IMAP) does **not** go through MediatR on the hot
path — see "Where MediatR stops" below.

```text
  WPF ViewModel                    SMTP/IMAP session            Kestrel endpoint
        │                                 │                            │
        │ IpcClient.SendAsync             │ (direct service calls)     │
        ▼                                 │                            ▼
  Named pipe (framed, ACL'd)              │                      MediatR ISender
        │                                 │                            │
        ▼                                 │                            │
  IpcCommandRegistry  ── explicit name→type map, never Type.GetType ───┤
        │                                                              │
        ▼                                                              ▼
                          MediatR ISender.Send(request)
                                        │
   ┌────────────────────────────────────┴─────────────────────────────────┐
   │                       PIPELINE BEHAVIORS (ordered)                   │
   │                                                                      │
   │  1. CorrelationBehavior      assign/flow CorrelationId + AdminOpId   │
   │  2. UnhandledExceptionBehavior  log + convert to typed app error     │
   │  3. PerformanceBehavior      stopwatch, warn over threshold          │
   │  4. LoggingBehavior          structured begin/end, redacted payload  │
   │  5. AuthorizationBehavior    IAuthorizedRequest → permission check   │
   │  6. ValidationBehavior       FluentValidation, aggregate failures    │
   │  7. TransactionBehavior      ITransactionalRequest → one DB txn      │
   │  8. AuditBehavior            IAuditableRequest → AuditRecord         │
   │                                                                      │
   └────────────────────────────────────┬─────────────────────────────────┘
                                        ▼
                                    Handler
                                        │
                     ┌──────────────────┼──────────────────┐
                     ▼                  ▼                  ▼
              IDomainRepository   IMessageStore    ICertificateManager
                     │                  │                  │
                     ▼                  ▼                  ▼
              SQL (Dapper)        Filesystem         ACME / DPAPI
```

### Ordering rationale

Order is not arbitrary and is asserted by a test:

* **Correlation first** so that every later behavior, including exception logging, has an
  id to attach.
* **Exception handling second (outermost real handler)** so it also catches failures thrown
  *by* validation, authorization and transaction behaviors, not merely by the handler.
* **Authorization before validation** so an unauthorized caller cannot use validation error
  messages as an oracle to probe for the existence of domains or mailboxes. This is a
  deliberate information-disclosure defence.
* **Validation before transaction** so a malformed request never opens a database
  transaction. This matters under SQLite, where writer transactions serialize.
* **Transaction before audit** so the audit record is written inside the same transaction
  as the change it describes. An audit trail that can disagree with the data it audits is
  worse than no audit trail.

### Marker interfaces drive the pipeline

Behaviors do not use reflection over attributes or naming conventions; they test for
interfaces. This keeps the behavior cheap and the intent greppable.

```csharp
public interface ICommand<out TResponse> : IRequest<TResponse>;
public interface IQuery<out TResponse> : IRequest<TResponse>;

/// Opt in to an ambient database transaction.
public interface ITransactionalRequest;

/// Opt in to audit-trail persistence. The request supplies its own descriptor
/// so that secrets are never reflected out of the request object.
public interface IAuditableRequest
{
    AuditDescriptor DescribeForAudit();
}

/// Opt in to permission enforcement.
public interface IAuthorizedRequest
{
    AdminPermission RequiredPermission { get; }
}
```

`RequiredPermission` is an **instance** property rather than a `static abstract` interface
member. Static abstracts would be more elegant, but reaching one requires a generic constraint
on the behavior (`where TRequest : IAuthorizedRequest`), which in turn makes the pipeline
depend on the container filtering constrained open generics correctly. An instance property is
reachable through a plain `is` test, costs nothing, and keeps a single unconstrained behavior
handling every request.

`IAuditableRequest.DescribeForAudit()` is the single most important detail here. A generic
"serialize the request and store it" audit behavior would happily write a new mailbox
password or an imported PFX passphrase into the audit table. Requiring each auditable
request to *state* what is safe to record makes rule 97 ("Never audit secret values")
structural.

### Where MediatR stops

MediatR is used for administrative use cases and for coarse-grained operations such as
"accept this message into the store". It is **not** used per-SMTP-verb or per-IMAP-command:
allocating a request object and walking eight behaviors for every `RCPT TO` on a server
handling hundreds of concurrent sessions is unjustifiable overhead, and the SMTP state
machine needs synchronous, ordered, per-connection decisions rather than a mediator.

Protocol code therefore depends on narrow application services
(`IInboundMailPipeline`, `IRelayPolicy`, `ISmtpAuthenticator`) which are themselves
Application-layer abstractions. The business logic still lives in the Application layer;
only the dispatch mechanism differs. This satisfies rule "Do not place business logic
inside protocol socket handlers" without paying a mediator tax on the hot path.

---

## 4. Windows Service architecture

### The service is the product

`MailServer.Admin` is a management console. Killing it, uninstalling it, or leaving it
locked has **no** effect on mail flow. The service owns every listener, every queue, every
timer and every certificate.

```text
┌──────────────────────────────────────────────────────────────────────────┐
│  AetherMail Server   (Windows Service, least-privilege service account)  │
│                                                                          │
│  Microsoft.Extensions.Hosting  ·  Serilog  ·  DI container               │
│                                                                          │
│  ┌────────────────── STARTUP GATES (ordered, blocking) ──────────────┐   │
│  │  1. ConfigurationValidationHostedService                          │   │
│  │       fail fast on invalid config — never start half-configured   │   │
│  │  2. DatabaseBootstrapHostedService                                │   │
│  │       connectivity check → backup (if risky) → run migrations     │   │
│  │  3. StorageBootstrapHostedService                                 │   │
│  │       verify data roots, ACLs, free space, write probe            │   │
│  │  4. CertificateBootstrapHostedService                             │   │
│  │       load bindings; never downgrade a valid cert                 │   │
│  └───────────────────────────────────────────────────────────────────┘   │
│                                   │                                      │
│         ┌─────────────────────────┼─────────────────────────┐            │
│         ▼                         ▼                         ▼            │
│  ── LISTENERS ──          ── PROCESSORS ──          ── MAINTENANCE ──     │
│  SmtpInbound (25)         OutboundDelivery          CertificateLifecycle  │
│  SmtpSubmission (587)     QueueScheduler            AcmeRenewal           │
│  SmtpImplicitTls (465)    ReportProcessor           DnsMonitoring         │
│  Imap (993)               InboundPipeline           Housekeeping          │
│  Pop3 (995, opt-in)       QuarantineReaper          BackupScheduler       │
│  Kestrel (80/443)         MetricsAggregator         HealthEvaluator       │
│  IpcServer (named pipe)                                                   │
│                                                                          │
│  ── CROSS-CUTTING SINGLETONS ──                                          │
│  MaintenanceModeState · HealthRegistry · TlsCertificateProvider           │
│  ConnectionAccountant · RateLimiterRegistry · CorrelationAccessor         │
└──────────────────────────────────────────────────────────────────────────┘
```

### `ResilientBackgroundService`

Every worker derives from one base class rather than raw `BackgroundService`. The default
`BackgroundService` behavior — an unhandled exception silently stops that worker, and since
.NET 6 by default takes the whole host down — is wrong for a mail server, where a transient
DNS failure in the DNS monitor must never stop SMTP.

The base class provides:

| Concern | Behavior |
|---|---|
| Fault isolation | Exceptions are caught per iteration; the worker restarts itself |
| Restart backoff | Exponential with jitter, capped; repeated failure escalates health to Critical |
| Graceful shutdown | Cooperative `CancellationToken`; listeners stop accepting, then drain in-flight sessions up to a configurable grace period |
| Health reporting | Each worker publishes `Healthy` / `Warning` / `Critical` / `Unknown` plus a reason to `HealthRegistry` |
| Structured logging | Every log line carries the worker name and correlation scope |
| Maintenance awareness | Workers consult `MaintenanceModeState` and park themselves when their function is paused |

`OperationCanceledException` during shutdown is treated as success, never as a fault — a
common bug that makes shutdown logs full of alarming noise.

### Graceful shutdown ordering

Shutdown is not "stop everything at once". Order matters for data integrity:

```text
1. Stop accepting new SMTP/IMAP/POP3 connections   (listeners close sockets)
2. Reject new IPC commands with SERVICE_STOPPING
3. Drain in-flight inbound sessions (finish or 451 them cleanly)
4. Let outbound deliveries in the DATA phase complete; do not abandon mid-DATA
5. Release queue leases held by this instance so nothing is stranded
6. Flush metrics + logs
7. Close database connections
```

Abandoning a delivery mid-`DATA` risks a duplicate message at the remote server, which is
why step 4 is explicit.

---

## 5. WPF administration architecture

```text
┌─────────────────────────────────────────────────────────────────────┐
│ MailServer.Admin (net10.0-windows, WPF, MVVM)                       │
│                                                                     │
│  App.xaml.cs → Generic Host → DI container → MainWindow             │
│                                                                     │
│  ┌───────────────┐  ┌─────────────────────────────────────────────┐ │
│  │ Shell         │  │ Content region                              │ │
│  │ (navigation)  │  │  DashboardView / DomainsView / QueueView …  │ │
│  │               │  │                                             │ │
│  │ Status strip: │  │  View  ──x──> no code-behind logic          │ │
│  │  connection   │  │    │                                        │ │
│  │  maintenance  │  │    │ DataContext                            │ │
│  │  health       │  │    ▼                                        │ │
│  │  lock state   │  │  ViewModel (CommunityToolkit.Mvvm)          │ │
│  └───────────────┘  │    │  ObservableProperty / RelayCommand     │ │
│                     │    │  ── NO business logic ──               │ │
│                     │    ▼                                        │ │
│                     │  IAdminGateway  (thin, typed façade)        │ │
│                     └────┬────────────────────────────────────────┘ │
│                          ▼                                          │
│                     IpcClient  → named pipe → Windows Service       │
└─────────────────────────────────────────────────────────────────────┘
```

### Key decisions

* **`IAdminGateway` is the only way out of the UI.** ViewModels depend on it, so they are
  unit-testable against a fake with no pipe and no service. It exposes typed methods
  (`GetDomainsAsync`, `CreateDomainAsync`) rather than a stringly-typed `Send(name, json)`.
* **ViewModels hold no business rules.** They hold presentation state: busy flags, selected
  item, validation *display*, sort order. Rules such as "a domain cannot be deleted while
  it still has mailboxes" live in the Domain/Application layers and surface to the UI as a
  typed error from IPC. The UI never re-implements a rule, so the two can never disagree.
* **Async all the way.** Every command is `IAsyncRelayCommand`. No `.Result`, no `.Wait()`,
  no `async void` except the framework-required event handlers, which immediately delegate
  to a guarded async method.
* **Navigation is centralized** in `INavigationService` with a registry of view-model types,
  so the shell does not accumulate a `switch` over page names.
* **The lock screen is a shell-level overlay** (Milestone 2). Locking the UI does not
  disconnect the IPC session's *service-side* work already in flight; it revokes the admin
  session token so subsequent commands are rejected.
* **Destructive operations require typed confirmation.** Deleting a domain requires the
  administrator to type the domain name, matching the interaction model of Windows Server
  tooling.

### Visual language

Dense, information-first, Windows Server Manager-like: compact `DataGrid`s, a fixed
left navigation tree, a status strip, colour used only for state (not decoration), and a
consistent four-state status vocabulary (`Healthy` / `Warning` / `Critical` / `Unknown`)
reused everywhere from health checks to certificate status. No animated gauges, no
"gamified" dashboards.

---

## 6. SMTP architecture

Three listener *roles*, one codebase, different policy profiles. Conflating MTA receipt
with client submission is the root cause of most open relays in the wild, so the roles are
distinct types with distinct policies, not a boolean flag.

| Role | Port | TLS | Auth | Relay allowed | Purpose |
|---|---|---|---|---|---|
| `InboundMta` | 25 | STARTTLS, opportunistic | Never offered | **Never** | Receive mail from the Internet for local domains |
| `Submission` | 587 | STARTTLS, **required before AUTH** | Required | Yes, for the authenticated mailbox | Mail clients |
| `ImplicitTlsSubmission` | 465 | Implicit TLS from byte zero | Required | Yes, for the authenticated mailbox | Mail clients |

### Session pipeline

```text
TCP accept
   │
   ├─ ConnectionAccountant: per-IP concurrent cap, global cap  ─► 421 if exceeded
   ├─ IP allow/deny list                                       ─► 554 if denied
   ├─ Connection-level rate limit                              ─► 421 if exceeded
   ▼
SmtpSession  (owns an explicit state machine — never ad-hoc string matching)
   │
   ▼
SmtpCommandReader  (bounded: max line 512B for commands / 1000B for extended,
                    max command length, max unrecognized commands, idle timeout)
   │
   ▼
SmtpCommandParser  → SmtpCommand record (verb + parsed parameters)
   │
   ▼
State machine transition table  → allowed? → SmtpCommandHandler
   │
   ▼
Per-verb policy (relay, size, recipient count, auth requirement)
   │
   ▼
DATA / BDAT  → streamed to IMessageStore staging (never fully buffered in RAM)
   │
   ▼
IInboundMailPipeline  (SPF → DKIM → DMARC → ARC → content → scoring → disposition)
   │
   ▼
Deliver local · Queue outbound · Quarantine · Reject
```

### Explicit state machine

```text
        ┌──────────┐  banner sent
        │Connected │───────────────┐
        └────┬─────┘               │
             │ EHLO/HELO           │ QUIT at any state
             ▼                     │
        ┌──────────┐               │
   ┌────│ Greeted  │◄──── RSET ────┼──────┐
   │    └────┬─────┘               │      │
   │         │ STARTTLS            │      │
   │         ▼                     │      │
   │  ┌─────────────┐  TLS ok      │      │
   │  │TlsNegotiated│──► reset to Greeted, capabilities re-advertised
   │  └─────────────┘  (state and all session data MUST be discarded)
   │         │ AUTH (submission only, TLS required)
   │         ▼
   │  ┌──────────────┐
   │  │Authenticated │
   │  └──────┬───────┘
   │         │ MAIL FROM
   │         ▼
   │  ┌──────────────────┐
   │  │ MailFromAccepted │
   │  └──────┬───────────┘
   │         │ RCPT TO (≥1)
   │         ▼
   │  ┌─────────────────────┐
   │  │ RecipientsAccepted  │◄── additional RCPT TO
   │  └──────┬──────────────┘
   │         │ DATA / BDAT
   │         ▼
   │  ┌──────────────┐
   │  │ ReceivingData│
   │  └──────┬───────┘
   │         │ terminal "." / final BDAT chunk
   │         ▼
   │  ┌────────────────┐
   └──│MessageAccepted │
      └────────────────┘
```

**The STARTTLS reset is a security-critical transition, not a convenience.** After a
successful TLS handshake the session discards the prior EHLO name, any buffered pipeline
data, and all envelope state. Failing to do so is the STARTTLS command-injection class of
bug (CVE-2011-0411 and relatives), where an attacker injects plaintext commands that are
then executed as if they arrived inside the TLS tunnel. A dedicated security test asserts
that plaintext bytes sent immediately before `STARTTLS` are discarded and never executed.

### Capability advertisement

`EHLO` advertises only what is implemented and currently permitted:

* `STARTTLS` is not advertised once TLS is already active.
* `AUTH` is never advertised on port 25 and is not advertised on 587 before TLS.
* `SIZE` reflects the effective limit for this connection (per-domain, per-mailbox).
* `SMTPUTF8`, `CHUNKING`, `DSN`, `REQUIRETLS`, `PIPELINING`, `8BITMIME`,
  `ENHANCEDSTATUSCODES` appear only when the corresponding feature has passing tests.
  Advertising an extension that is not honoured is worse than not advertising it, because
  peers make delivery decisions based on it.

### Relay decision — the single most important function in the product

```csharp
// Pseudocode of MailServer.Application.Mail.RelayPolicy — the real implementation
// is total (no default-allow branch exists anywhere in it).
RelayDecision Evaluate(SmtpSessionContext session, EmailAddress recipient)
{
    if (IsLocalDomain(recipient.Domain))        return RelayDecision.AcceptLocal;
    if (session.IsAuthenticated
        && session.Role is Submission or ImplicitTlsSubmission
        && SenderMayRelay(session.Mailbox, recipient))
                                                return RelayDecision.AcceptRelay;
    if (IsAuthorizedRelayIp(session.RemoteIp))  return RelayDecision.AcceptRelay;
    return RelayDecision.Deny;                  // 554 5.7.1
}
```

The function is written so that `Deny` is the fall-through. There is no configuration
switch anywhere in the product that turns port 25 into an open relay, and the automated
test suite attempts a relay through every listener role in every authentication state.

---

## 7. IMAP architecture

```text
TLS accept (993 implicit) ──► ImapSession
                                  │
                                  ├─ ImapCommandReader  (tag + command + literals)
                                  │     literal handling: {n} and {n+} with a hard cap,
                                  │     streamed to disk above a threshold
                                  ├─ ImapCommandParser  → typed command record
                                  ├─ State machine: NotAuthenticated → Authenticated
                                  │                  → Selected → Logout
                                  ├─ IMailboxSession   (per-selected-folder view)
                                  │     UIDVALIDITY, UIDNEXT, HIGHESTMODSEQ, flags
                                  └─ ImapResponseWriter (untagged then tagged, ordered)
```

### State correctness is the hard part

An IMAP server that gets `UID`/`UIDVALIDITY` semantics wrong causes clients to silently
re-download or, far worse, delete mail. The invariants enforced:

* **UIDs are monotonically increasing per folder and never reused**, even after `EXPUNGE`.
  Implemented as a per-folder `UidNext` counter allocated inside the same transaction that
  inserts the message row, with a unique constraint on `(FolderId, Uid)`.
* **`UIDVALIDITY` changes only when UID continuity is broken** (folder deleted and
  recreated, or restored from a backup that rewound UIDs). It is stored, not derived from a
  timestamp at runtime.
* **Sequence numbers are per-session and recomputed on expunge.** The session holds the
  message-set snapshot; untagged `EXPUNGE` responses are emitted in descending sequence
  order so clients renumber correctly.
* **No untagged `EXPUNGE` is sent during a `FETCH`/`STORE`/`SEARCH`** (forbidden by
  RFC 3501); pending expunges are queued and flushed at a permitted point.
* **`\Recent` is implemented honestly.** Because correct `\Recent` semantics require
  exactly one session to "own" the flag, and most modern clients ignore it, the server
  reports `\Recent` conservatively rather than incorrectly.
* **`IDLE` holds the connection with a server-side timer** that emits a `NOOP`-equivalent
  before the 29-minute RFC 2177 limit, and is cancelled cleanly on shutdown.

### Special-use folders

`Inbox`, `Sent`, `Drafts`, `Trash`, `Junk`, `Archive` are created with the mailbox and
advertised via `SPECIAL-USE` (`\Sent`, `\Drafts`, `\Trash`, `\Junk`, `\Archive`) so clients
stop creating duplicates like `Sent Items` alongside `Sent`.

### POP3

Disabled by default, implemented in `MailServer.Protocols.Pop3` for legacy device
compatibility only. POP3's destructive-read model interacts badly with IMAP on the same
mailbox; the admin UI warns about this when enabling it.

---

## 8. Outbound queue architecture

```text
Submission / forwarding / DSN generation
        │
        ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  OutboundQueueItem  (one row per recipient, not per message) │
  │  Message body stored ONCE in IMessageStore; rows reference it│
  └──────────────────────────────┬───────────────────────────────┘
                                 ▼
             QueueSchedulerHostedService  (leases work)
                                 │
                 SELECT … WHERE Status=Pending AND NextAttemptUtc<=now
                       ORDER BY Priority, NextAttemptUtc
                       → atomically mark Processing + set LeaseExpiresUtc + LeaseOwner
                                 │
                                 ▼
             Group by destination domain → DomainDeliveryChannel
                                 │
   per-domain: max concurrency · connection rate · deferral backpressure
                                 │
                                 ▼
                    OutboundDeliveryHostedService (N workers)
                                 │
        MX lookup (cached) → priority ordering → A/AAAA → connect 25
        EHLO → STARTTLS (policy-driven) → MAIL FROM → RCPT TO → DATA/BDAT
                                 │
                                 ▼
                    SmtpReplyClassifier → DeliveryOutcome
                                 │
   ┌─────────────┬───────────────┼───────────────┬──────────────┐
   ▼             ▼               ▼               ▼              ▼
Delivered    Deferred(4xx)   Bounced(5xx)    TlsRequired    Cancelled
   │             │               │            Failure           │
   │        NextAttempt =        │               │              │
   │        backoff(attempt)     │               │              │
   │             │               ▼               ▼              │
   │             │          Generate DSN    Do NOT downgrade    │
   │             │          MAIL FROM:<>    to plaintext        │
   └─────────────┴───────────────┴───────────────┴──────────────┘
                                 ▼
                      DeliveryAttempt row (always written)
```

### Decisions

* **One row per recipient.** A message to 50 recipients across 12 domains must be able to
  succeed for 49 and defer for 1. Per-message rows make partial success unrepresentable.
* **Leasing, not locking.** A worker claims work by writing `Processing` + `LeaseOwner` +
  `LeaseExpiresUtc`. A crashed worker's items are reclaimed when the lease expires —
  no orphaned `Processing` rows requiring manual intervention. This also makes the design
  ready for multiple service instances later.
* **Every attempt is recorded**, including the remote MX hostname, remote IP, TLS version,
  cipher, peer certificate subject/issuer, full SMTP reply and enhanced status code. This
  is what makes "why did Gmail reject this?" answerable months later.
* **Backoff is a pure, unit-tested policy** (`RetryBackoffPolicy`) with jitter. Defaults:
  1m, 5m, 15m, 30m, 1h, 2h, 4h, 8h, then every 6h until the expiry window (default 5 days),
  with a warning DSN at 4 hours. All configurable.
* **5xx never retries.** Permanent failures bounce immediately. A 5xx that is retried is
  both useless and a reputation liability.
* **Provider throttling is respected, never circumvented.** When a destination returns
  deferrals or explicit rate-limit responses, the per-domain channel *reduces* concurrency
  and *increases* spacing. There is no IP rotation, no connection-count escalation, and no
  retry-storm behavior. This is a deliberate product boundary.

### Bounce-loop prevention

A generated DSN uses the null reverse path `MAIL FROM:<>`. A message that itself has a null
reverse path and fails **never** generates another DSN; it is recorded and dropped to the
postmaster-visible failure log. Additionally, `Auto-Submitted: auto-replied` is set, and a
DSN is never generated for a message already carrying `Auto-Submitted` other than `no`.

---

## 9. SQLite architecture

SQLite is a first-class supported provider for development, small deployments and appliance
installs — not a toy mode. Its concurrency model dictates specific design choices.

| Setting | Value | Reason |
|---|---|---|
| `journal_mode` | `WAL` | Readers never block the writer; essential when IMAP reads while the queue writes |
| `synchronous` | `NORMAL` (WAL) | Durable across process crash; `FULL` costs too much per queue update |
| `busy_timeout` | 5000 ms (configurable) | Converts `SQLITE_BUSY` into a bounded wait instead of an immediate error |
| `foreign_keys` | `ON` | Off by default in SQLite; referential integrity must be explicit |
| `cache_size` | negative KiB form | Bounded memory rather than page count |
| Pooling | enabled | `Microsoft.Data.Sqlite` pools connections; each still applies pragmas on open |

### The write-serialization decision

SQLite permits exactly one writer. Multiple queue workers competing for write transactions
produce `SQLITE_BUSY` storms and long tail latencies. Therefore, under SQLite only:

* A single `SqliteWriteGate` (an `AsyncSemaphore` of 1) serializes *write* transactions
  in-process. Reads are unrestricted and run concurrently thanks to WAL.
* Write transactions are kept short and never span a network call. The pattern "open
  transaction → SMTP delivery → commit" is forbidden; delivery happens outside the
  transaction and the result is recorded in a second short transaction.
* Queue leasing uses `UPDATE … WHERE Id IN (SELECT … LIMIT n) RETURNING …`, a single
  statement rather than select-then-update.

`ISqlDialect` exposes `RequiresSerializedWrites`, so the gate exists only for SQLite and is
a no-op under SQL Server. This is the one place where a provider difference leaks upward,
and it leaks as a capability flag rather than as a type check.

### Positioning

SQLite is recommended up to roughly a few dozen mailboxes and modest sustained volume. The
admin UI states this plainly and offers the SQLite → SQL Server migration tool (Milestone
13) rather than letting an installation quietly outgrow its database.

---

## 10. SQL Server architecture

| Concern | Approach |
|---|---|
| Connectivity | `Microsoft.Data.SqlClient`, `Encrypt=True` by default; `TrustServerCertificate` is **off** by default and requires explicit opt-in with a logged warning |
| Auth | Integrated Security (service account) preferred; SQL auth password stored via DPAPI, never in plaintext config |
| Resilience | Built-in connection retry plus an application-level retry policy for the documented transient error numbers (1205 deadlock, 1222 lock timeout, 49918/40501/40197 throttling, 4060, 40613) |
| Isolation | `READ COMMITTED` with `READ_COMMITTED_SNAPSHOT ON` set by migration, so readers do not block writers — matching the WAL semantics the SQLite provider gives |
| Queue leasing | `UPDATE TOP (@n) … WITH (READPAST, UPDLOCK, ROWLOCK) … OUTPUT inserted.*` — the canonical high-throughput SQL Server queue pattern; multiple workers skip each other's locked rows instead of blocking |
| Bulk paths | `SqlBulkCopy` for metrics rollups, DMARC/TLS report ingestion and the SQLite→SQL Server migration |
| Indexing | Filtered indexes on hot queue predicates (`WHERE Status IN (0,2)`), covering indexes for the queue grid, and columnstore considered for the metrics fact table at scale |
| Backups | Native `BACKUP DATABASE … WITH CHECKSUM, COMPRESSION` + `RESTORE VERIFYONLY`. Copying MDF/LDF files is explicitly rejected |

SQL Server is the recommended production provider. The recommendation is stated in the
setup wizard, the docs, and the deliverability/health report.

---

## 11. SQL migration strategy

### Decision: a custom migration runner over numbered SQL scripts

Evaluated against DbUp and FluentMigrator:

| Option | Verdict |
|---|---|
| **FluentMigrator** | Rejected. Its C# DSL abstracts over provider differences, which is exactly what we do *not* want: we need hand-tuned filtered indexes, `READ_COMMITTED_SNAPSHOT`, `OUTPUT` clauses and SQLite pragmas. Fighting the abstraction would cost more than writing SQL. |
| **DbUp** | Close second. Solid, embedded-script based. Rejected because we need a few behaviors it does not provide out of the box: pre-upgrade automatic backup, checksum drift detection with a clear operator error, and per-provider script sets selected at runtime. Its model is, however, the one we imitate. |
| **Custom runner** | **Chosen.** ~300 lines, fully testable, no external dependency in the data path, and does exactly the four things production upgrades require. |

### Layout

```text
src/MailServer.Persistence.Sqlite/Migrations/
    0001_InitialSchema.sql
    0002_AddDkimKeys.sql
src/MailServer.Persistence.SqlServer/Migrations/
    0001_InitialSchema.sql
    0002_AddDkimKeys.sql
```

Scripts are **embedded resources**, so a deployment cannot be missing them and an operator
cannot accidentally edit an applied migration on disk.

### `SchemaVersion` table

```sql
CREATE TABLE SchemaVersion (
    Version        INTEGER      NOT NULL PRIMARY KEY,
    Name           TEXT         NOT NULL,
    Checksum       TEXT         NOT NULL,   -- SHA-256 of normalized script text
    AppliedUtc     TEXT         NOT NULL,
    DurationMs     INTEGER      NOT NULL,
    AppliedBy      TEXT         NOT NULL,   -- machine\service account
    ProductVersion TEXT         NOT NULL
);
```

### Guarantees

1. **Never twice.** Applied versions are read first; only higher unapplied versions run.
2. **Transactional where supported.** Each script runs inside a transaction and is rolled
   back on failure. SQL Server batches are split on `GO`. Statements that cannot run inside
   a transaction are marked with a `-- @NoTransaction` header directive and run outside it,
   deliberately and visibly.
3. **Checksum drift is a hard error.** If an already-applied script's checksum no longer
   matches, the service refuses to start with an actionable message. Silently ignoring an
   edited migration is how environments diverge irreparably.
4. **Fail safe.** A failed migration aborts startup. The service does not run against a
   half-migrated schema.
5. **Backup before risky upgrades.** Migrations declaring `-- @Destructive` trigger an
   automatic backup first (SQLite: file copy of a checkpointed database; SQL Server:
   `BACKUP DATABASE`). Refusing to back up aborts the upgrade.
6. **Advisory lock.** Concurrent starts cannot race: SQL Server uses
   `sp_getapplock`; SQLite relies on its single-writer guarantee plus a lock row.
7. **Ordering is explicit** — a four-digit zero-padded integer parsed from the filename.
   Duplicate versions fail at startup, not at deploy time.

---

## 12. Transaction strategy

### Explicit boundaries, owned by the Application layer

```csharp
public interface ITransactionManager
{
    Task<T> ExecuteAsync<T>(
        Func<DbConnection, DbTransaction, CancellationToken, Task<T>> action,
        CancellationToken cancellationToken);

    Task ExecuteAsync(
        Func<DbConnection, DbTransaction, CancellationToken, Task> action,
        CancellationToken cancellationToken);
}
```

### Rules

| Rule | Rationale |
|---|---|
| Commands that mutate state implement `ITransactionalRequest`; `TransactionBehavior` opens **one** transaction around the handler | Prevents partially-applied use cases |
| Queries never open a transaction | Avoids needless writer contention, critical under SQLite |
| The ambient transaction flows via a scoped `IAmbientTransaction`, not a static/`AsyncLocal` global | Rule 111 forbids static mutable state; scoped DI makes the lifetime explicit |
| Nested `ExecuteAsync` calls **join** the ambient transaction rather than opening a second connection | Prevents self-deadlock under SQLite's single-writer model |
| No `TransactionScope`, ever | `TransactionScope` can silently promote to MSDTC; a mail server must not acquire a distributed-transaction dependency |
| No network I/O inside a transaction | An SMTP conversation inside a DB transaction holds the SQLite writer for seconds |
| Filesystem writes happen **before** the transaction; the transaction records the reference | See §13 |

### The store-then-commit ordering

Message ingestion is a two-resource operation (filesystem + database) with no distributed
transaction available. The ordering chosen is:

```text
1. Write MIME to a temp file, flush, fsync, hash
2. Atomically move into its final content-addressed path
3. BEGIN TRANSACTION
4.   INSERT message metadata referencing that path
5. COMMIT
6. Acknowledge to the SMTP peer (250)
```

A crash between 2 and 5 leaves an orphaned blob — recoverable, invisible to users, and
reaped by `HousekeepingHostedService`. The opposite ordering would leave a database row
pointing at a nonexistent file, which is user-visible data loss. **We always fail toward
an orphaned blob, never toward a dangling reference.** The peer is acknowledged only after
commit, so a crash before step 6 results in the sender retrying — a duplicate, which SMTP
explicitly tolerates and loss, which it does not.

---

## 13. Message storage architecture

Relational rows hold metadata; MIME bytes live on the filesystem behind `IMessageStore`.
Storing multi-megabyte attachments in table rows destroys backup times, buffer-pool
efficiency and restore windows.

```text
Data/
  Messages/    delivered mail, content-addressed
  Queue/       outbound bodies awaiting delivery
  Temp/        staging for in-flight DATA; same volume as target (atomic move)
  Quarantine/  isolated, non-executable, scanner-visible
  Certificates/ PFX/keys (DPAPI-protected), ACLs to service account only
  Backups/
  Logs/
  Reports/     inbound DMARC/TLS-RPT before parsing
```

### Path scheme

```text
Messages/2026/09/ab/cd/01J9Z8Q7XKACME000000000001.eml
         ^^^^ ^^ ^^ ^^
         year mo  two 2-hex-char shard levels derived from the ID hash
```

Two shard levels keep any single directory to a few thousand entries, which matters on NTFS
where huge directories degrade enumeration badly.

### Safety guarantees

* **Identifiers are server-generated ULIDs.** No component of a stored path is ever derived
  from user input — not the sender, not the subject, not the client-supplied filename.
  Path traversal is impossible because there is no untrusted string in the path at all.
* **A final containment check** still runs: the resolved absolute path must sit under the
  configured root (`Path.GetFullPath` + ordinal prefix comparison with a trailing
  separator). Defence in depth for a bug, not for input.
* **Atomic writes:** write to `Temp/` on the same volume → `FlushAsync` → `File.Move` with
  `overwrite: false`. A partially written `.eml` is never visible under `Messages/`.
* **SHA-256 recorded at write time** so backup verification and corruption detection are
  possible without re-reading every message twice.
* **Streaming end to end.** `DATA` is read in bounded chunks straight to disk; IMAP `FETCH`
  streams from disk to socket. Rule 76 ("Do not load entire large messages into RAM") is
  enforced by the `IMessageStore` API surface itself — it exposes `Stream`, and there is no
  `byte[] ReadAll()` method to misuse.
* **Attachment de-duplication** is possible later because storage is content-addressed;
  the API does not preclude it.

---

## 14. Certificate architecture

TLS is a first-class subsystem, not a configuration detail.

```text
                     ┌──────────────────────────────┐
                     │  ICertificateManager         │  ← Application port
                     └──────────────┬───────────────┘
                                    │
        ┌─────────────┬─────────────┼─────────────┬──────────────────┐
        ▼             ▼             ▼             ▼                  ▼
  SelfSigned     AcmeProvider   PfxImport   WindowsCertStore    (future CAs)
  Generator      (Certes)       Provider    Provider
        └─────────────┴─────────────┴─────────────┴──────────────────┘
                                    │  produces
                                    ▼
                        ┌────────────────────────┐
                        │  CertificateBinding    │  hostname → cert + purpose
                        └───────────┬────────────┘
                                    ▼
                     ┌──────────────────────────────┐
                     │  TlsCertificateProvider      │  singleton, hot-swappable
                     │  (atomic reference swap)     │
                     └──────────────┬───────────────┘
             ┌──────────┬───────────┼───────────┬──────────┐
             ▼          ▼           ▼           ▼          ▼
          SMTP 25   SMTP 587    SMTP 465    IMAP 993   HTTPS 443
```

### Hot reload without restart

Listeners never capture an `X509Certificate2` at startup. They call
`SslStream.AuthenticateAsServerAsync` with a `ServerCertificateSelectionCallback` that asks
`TlsCertificateProvider` on **every handshake**. Renewal therefore becomes a single
`Interlocked.Exchange` of an immutable snapshot — new connections use the new certificate,
in-flight sessions finish on the old one, and nothing restarts. The previous certificate is
retained for a rollback window.

### Non-negotiable fallback policy

```text
Renewal fails and the current certificate is still valid
    → KEEP the current certificate
    → log Critical, raise a health alert, notify the administrator
    → retry with backoff
    → NEVER substitute a self-signed certificate
```

Silently downgrading a publicly trusted certificate to self-signed would turn a renewal
warning into a fleet-wide TLS failure with remote MTAs and every mail client. A self-signed
certificate is only ever used where one was explicitly chosen, or at first bootstrap when
no certificate exists at all.

---

## 15. Let's Encrypt / ACME lifecycle

```text
FIRST ISSUANCE
  1. Create/load ACME account key            (DPAPI-protected, never logged)
  2. Register account, accept ToS, set contact email
  3. Pre-flight: does DNS point here? is :80 reachable? (fail early, not at the CA)
  4. Create order for the identifier set (mail.example.com, mta-sts.example.com, …)
  5. Fetch authorizations → select challenge
        HTTP-01 → publish token via Kestrel /.well-known/acme-challenge/{token}
        DNS-01  → IDnsChallengeProvider.CreateTxtRecordAsync(_acme-challenge.…)
                  → poll authoritative nameservers for propagation
  6. Notify CA to validate → poll authorization status with bounded backoff
  7. Generate a NEW key pair (never reuse), build CSR, finalize order
  8. Download certificate chain
  9. Validate: chain builds, hostname matches, private key present and usable
 10. Persist (DPAPI-protected PFX or Windows cert store)
 11. Update CertificateBinding → TlsCertificateProvider hot-swap
 12. Audit + clean up the challenge artifact (always, including on failure)

RENEWAL  (CertificateLifecycleHostedService, default every 12h)
  daysRemaining ≤ 30 → attempt renewal
  daysRemaining ≤ 21/14/7 → escalate health severity at each threshold
  failure → keep existing cert, exponential backoff, alert; NEVER downgrade
  success → same steps 7–12
```

### Operational safeguards

* **Staging first.** The setup wizard defaults new installations to the Let's Encrypt
  **staging** directory for a trial issuance, then switches to production. This avoids
  burning production rate limits (50 certificates per registered domain per week, 5
  duplicate certificates per week, 5 failed validations per account per hostname per hour)
  while an administrator is still fixing DNS.
* **Rate-limit awareness is built in.** The client tracks recent issuance attempts per
  registered domain locally and refuses to submit an order that would obviously breach a
  documented limit, explaining why. Hammering the CA gets an installation blocked.
* **Idempotent challenge cleanup** in a `finally` block. A stale `_acme-challenge` TXT
  record or leftover HTTP token is both a hygiene and a security problem.
* **Certes** is used for ACME protocol and JWS handling. Hand-rolling ACME's JWS signing,
  nonce handling and key authorization digests is an unnecessary cryptographic risk.

---

## 16. Self-signed certificate strategy

Generated with `CertificateRequest` + `RSA` from the BCL — no external dependency.

| Property | Value |
|---|---|
| Key | RSA 3072 (default; 2048 and 4096 offered) |
| Signature | SHA-256 |
| EKU | Server Authentication (1.3.6.1.5.5.7.3.1) only |
| Basic constraints | `CA=false`, critical |
| Key usage | `DigitalSignature | KeyEncipherment`, critical |
| SAN | `mail.example.com` (+ every configured hostname; CN alone is ignored by modern clients) |
| Validity | Configurable: 1 / 2 / 5 years, default 1 |
| Key storage | Exportable=false where the store permits; DPAPI-protected PFX otherwise |

**Every surface that displays a self-signed certificate shows this warning verbatim:**

```text
SELF-SIGNED CERTIFICATES ARE NOT PUBLICLY TRUSTED.
MAIL CLIENTS AND REMOTE SYSTEMS MAY DISPLAY CERTIFICATE WARNINGS.
USE LET'S ENCRYPT OR ANOTHER PUBLIC CA FOR INTERNET-FACING PRODUCTION SERVERS.
```

The deliverability score deducts the full "certificate trust" weighting for a self-signed
certificate on an Internet-facing server, so the cost is visible as a number, not just a
banner.

---

## 17. Windows Certificate Store strategy

* Production certificates may live in `LocalMachine\My`, referenced by thumbprint.
* Private keys are **not** exported to disk when the store holds them. The service account
  is granted read access to the key container via the CNG/CAPI key security descriptor —
  the narrowest grant that works, applied by the installer.
* The store is read through `X509Store` with `OpenFlags.ReadOnly` at runtime.
  Installation/renewal into the store is a separate, audited, elevated operation.
* Chain validation uses `X509Chain` with explicit policy: revocation check online with
  offline fallback, and `X509VerificationFlags.NoFlag` — **no** `TrustServerCertificate`,
  **no** `RemoteCertificateValidationCallback` that returns `true`. Rule 105 ("No
  certificate validation bypass") is verified by a security test that greps the compiled
  assemblies' IL for callbacks returning constant `true`.
* Where a certificate must be persisted outside the store (e.g. bootstrapping before the
  store is configured), it is written as a DPAPI-protected PFX with a randomly generated
  passphrase held in the DPAPI-protected secret store, under ACLs granting the service
  account alone.

---

## 18. DNS architecture

Two distinct DNS consumers with different requirements, behind two abstractions:

```csharp
// Hot path: MX resolution for delivery. Cached, bounded, fast.
public interface IDnsResolver
{
    Task<IReadOnlyList<MxRecord>> ResolveMxAsync(DomainName d, CancellationToken ct);
    Task<IReadOnlyList<IPAddress>> ResolveHostAsync(string host, CancellationToken ct);
    Task<IReadOnlyList<string>> ResolveTxtAsync(string name, CancellationToken ct);
    Task<IReadOnlyList<string>> ResolvePtrAsync(IPAddress ip, CancellationToken ct);
}

// Diagnostics: must bypass cache and may query authoritative servers directly.
public interface IDnsDiagnosticsService
{
    Task<DnsLookupResult> LookupAsync(DnsQuery q, CancellationToken ct);
}
```

| Concern | Decision |
|---|---|
| Library | `DnsClient.NET` — mature, async, honours TTLs, supports arbitrary record types and explicit server selection |
| Caching | Respect TTL, with a configured floor (30 s) and ceiling (1 h). Negative caching with a shorter TTL. Prevents both stale MX data and DNS amplification of our own traffic |
| Failure semantics | `SERVFAIL`/timeout on MX lookup is a **temporary** failure (4xx, retry). `NXDOMAIN` is **permanent** (5xx, bounce). Conflating these causes either lost mail or infinite retries |
| MX selection | Group by priority, shuffle within a priority band (RFC 5321 §5.1), try in order, remember per-host failures for the retry window |
| Implicit MX | A domain with no MX but an A/AAAA record falls back to that host, per RFC 5321 |
| Null MX | `0 .` is honoured as "this domain accepts no mail" → immediate permanent failure |
| IPv6 | AAAA is attempted when the server has working IPv6 egress; Happy-Eyeballs-style preference is configurable, because many operators' IPv6 reputation is worse than their IPv4 |
| DNSSEC | Not validated in v1. `IDnsResolver` exposes an `IsAuthenticatedData` flag so DANE (§54) can be enabled later only when validation is genuinely available. Claiming DANE without DNSSEC validation would be actively harmful |
| Diagnostics | Queries authoritative nameservers directly and reports TTL, the answering server, and the actual vs expected value, so "it works on my resolver" is diagnosable |

---

## 19. DKIM / SPF / DMARC architecture

### Outbound: DKIM signing

```text
Message accepted for submission
   → canonicalize (relaxed/relaxed default; simple/simple available)
   → select active DkimKey for the From: domain
   → build DKIM-Signature with h= over a curated, stable header set
     (From, To, Cc, Subject, Date, Message-ID, MIME-Version, Content-Type, …)
     From is ALWAYS signed and oversigned (listed twice) to block header-injection replay
   → sign body hash (bh=) over the canonicalized body, with l= omitted by default
   → prepend the header
```

`l=` (body length) is omitted by default because it enables content-append attacks. Key
rotation is `generate → publish DNS → verify propagation → activate → retire old after a
grace window`, never a hard swap that breaks in-flight mail.

### Inbound: authentication evaluation

```text
Inbound message
  ├─ SPF   (RFC 7208) — evaluated against the SMTP MAIL FROM, with HELO fallback.
  │         Enforces the 10 DNS-lookup limit and the 2 void-lookup limit; exceeding
  │         them is `permerror`, not "keep going".
  ├─ DKIM  (RFC 6376) — verify every signature; a message may carry several.
  ├─ DMARC (RFC 7489) — discover policy at _dmarc.<From domain> with public-suffix
  │         aware organizational-domain fallback. Evaluate alignment:
  │            SPF alignment:  MAIL FROM domain vs From domain (relaxed/strict)
  │            DKIM alignment: d= domain vs From domain (relaxed/strict)
  │         PASS if at least one aligned mechanism passes.
  └─ ARC   (RFC 8617) — validate the chain when present; used to rescue legitimate
            forwarded mail that fails SPF/DKIM for structural reasons.
```

Results are written into a **local** `Authentication-Results` header stamped with our own
`authserv-id`. Pre-existing `Authentication-Results` headers from untrusted upstreams are
**stripped or renamed** before ours is added — trusting an attacker-supplied
`Authentication-Results: dmarc=pass` header is a complete authentication bypass.

### Public Suffix List

DMARC organizational-domain computation requires the PSL. It ships with the product and is
refreshed by `HousekeepingHostedService`; a stale PSL produces subtly wrong alignment
results, so its age is a health check.

### Forwarding and SRS

Plain forwarding breaks SPF. Sender Rewriting Scheme rewrites the envelope sender to a
locally-signed, time-limited, HMAC-authenticated address so that the forwarding hop passes
SPF while the `From:` header, and therefore DMARC alignment via DKIM, is untouched. The
forward path preserves the original DKIM signature bit-for-bit — re-encoding a forwarded
message is the most common way self-hosted servers break DMARC for their users.

---

## 20. Deliverability architecture

Deliverability is treated as a measurable product feature with a scoring model, not as
advice in a wiki.

```text
IDeliverabilityCheck (one per concern, independently testable)
   ├─ Identity:        A/AAAA, PTR, FCrDNS, EHLO name matches PTR
   ├─ Authentication:  SPF present & sane, DKIM published & matches key, DMARC present,
   │                   alignment verified by an actual self-test message
   ├─ TLS:             cert trusted, hostname matches, expiry, renewal healthy,
   │                   STARTTLS offered, MTA-STS policy served, TLS-RPT published
   ├─ DNS:             MX correct, no lookup-limit breach, TTL sanity, CAA sanity
   ├─ Reputation:      IReputationProvider results (cached, rate-limited)
   └─ Operations:      open-relay test, queue health, disk, clock skew, bounce rate
                            │
                            ▼
              DeliverabilityScoreCalculator
   Identity 20 · Authentication 30 · TLS 20 · DNS 15 · Reputation 10 · Operations 5
                            │
                            ▼
       Score + per-check contribution + remediation text for every deduction
```

Every check returns `Pass` / `Warn` / `Fail` / `Inconclusive` **with evidence** (the actual
record found, the expected value, the resolver used, the TTL). The UI shows exactly how the
score was computed — a bare "94/100" that cannot be explained is useless to an operator.

**The product never guarantees inbox placement.** The UI says "readiness", not
"guaranteed delivery", and the docs state that reputation is earned over time through
sending behavior no software can shortcut.

`IReputationProvider` is an abstraction with caching and rate limiting because naive DNSBL
querying from a busy MTA both gets you blocked by the DNSBL operator and is an abuse of
volunteer infrastructure.

---

## 21. Security architecture

### Threat model (abbreviated)

| Threat | Mitigation |
|---|---|
| Open relay | Deny-by-default relay policy; automated relay tests across every listener/auth-state combination |
| Credential theft | Argon2id hashing; AUTH only over TLS; never logged; constant-time comparison |
| Credential stuffing / brute force | Per-IP and per-account throttling with exponential lockout; generic failure messages to prevent username enumeration |
| STARTTLS command injection | Full session-state reset after the handshake; explicit test |
| SQL injection | Parameterized SQL exclusively; no string concatenation of user input; a security test asserts no dynamic SQL construction from untrusted values |
| Path traversal | Server-generated identifiers only; containment check as defence in depth |
| Resource exhaustion (Slowloris, huge DATA, RCPT floods, MIME bombs, zip bombs, huge FETCH) | Bounded reads everywhere, idle/absolute timeouts, per-command and per-session limits, MIME depth/part caps, decompression ratio caps, streaming |
| Privilege escalation via IPC | Named pipe restricted by ACL to the administrators group + service account; authenticated admin session; explicit command registry (no `Type.GetType` from the wire); per-command permission checks |
| Secret disclosure | DPAPI-protected secret store; ACLs; a logging redaction filter; audit records that describe rather than dump |
| Malicious inbound content | Layered pipeline; quarantine; `IMalwareScanner` delegating to a real engine, never a home-grown one |
| Supply-chain | Central package management, pinned versions, `NuGet.config` restricted to nuget.org, lock files in CI |

### Defence-in-depth layers

```text
Network        Windows Firewall rules created only for enabled services
Connection     IP allow/deny, per-IP concurrency, connection rate limits
Protocol       Bounded parsers, strict state machines, size caps, timeouts
Authentication Argon2id, TLS-required, throttling, lockout
Authorization  Per-command permissions on every IPC operation
Content        SPF/DKIM/DMARC/ARC, spam scoring, attachment policy, malware scan
Data           DPAPI secrets, ACLs, parameterized SQL, hashed passwords
Audit          Every privileged action recorded with actor, target and result
```

### Secrets

`ISecretProtector` wraps DPAPI (`DataProtectionScope.LocalMachine` with an additional
entropy value stored in an ACL-protected file, so a copied database alone is insufficient).
Protected: DKIM private keys, ACME account keys, certificate passphrases, SQL auth
passwords, smarthost credentials, SRS and unsubscribe HMAC keys.

DPAPI is Windows-only. On non-Windows *development* machines a clearly-named
`DevelopmentSecretProtector` exists; it requires explicit opt-in configuration, refuses to
run when the environment is `Production`, and logs a Critical warning on every start. There
is no silent insecure fallback.

---

## 22. Recommended NuGet packages, with justification

Central Package Management (`Directory.Packages.props`) pins one version per package for
the whole solution. `NuGet.config` restricts sources to nuget.org.

| Package | Version | Why this, and why not hand-rolled |
|---|---|---|
| `MediatR` | **12.5.0** | CQRS dispatch + pipeline behaviors. **Pinned to 12.5.0 deliberately: it is the last Apache-2.0 release.** v13+ is under a commercial licence (see §28 Risks) |
| `FluentValidation` | 12.1.1 | Declarative, composable, testable validators; async rules; integrates cleanly as a pipeline behavior |
| `Dapper` | 2.1.86 | Thin mapper over ADO.NET. No change tracking, no query translation, no hidden SQL. Exactly the "explicit SQL" the brief requires |
| `Microsoft.Data.Sqlite` | 10.0.12 | First-party SQLite provider with pragma and pooling control |
| `Microsoft.Data.SqlClient` | 7.0.3 | First-party SQL Server driver; modern TLS defaults, Always Encrypted and AAD auth available later |
| `Microsoft.Extensions.Hosting` | 10.0.x | Generic Host: DI, configuration, logging, hosted-service lifetime |
| `Microsoft.Extensions.Hosting.WindowsServices` | 10.0.12 | Correct SCM integration, service lifetime, and Windows Event Log wiring |
| `Serilog.Extensions.Hosting` + sinks (`Console`, `File`, `EventLog`) | 10.0.0 / 6.x / 7.x | Structured logging with correlation enrichment, rolling files with retention, and selective Event Log escalation |
| `CommunityToolkit.Mvvm` | 8.4.2 | Source-generated `ObservableProperty`/`RelayCommand`. Removes boilerplate without a heavyweight MVVM framework |
| `Konscious.Security.Cryptography.Argon2` | 1.3.x | Argon2id for master and mailbox passwords. The BCL has no Argon2; PBKDF2 is materially weaker against GPU attack (Milestone 2) |
| `MimeKit` | 4.x | MIME parsing/generation, header encoding, DKIM canonicalization helpers. Writing a MIME parser by hand is a well-documented source of security bugs (Milestone 6) |
| `DnsClient` | 1.8.x | Async DNS with TTL handling, arbitrary record types and explicit server selection — `Dns.GetHostEntry` cannot do MX/TXT/PTR properly (Milestone 8) |
| `Certes` | 3.x | ACME v2 with correct JWS. Hand-implementing ACME cryptography is an unnecessary risk (Milestone 4) |
| `System.IO.Hashing` | 10.0.x | Fast non-cryptographic hashing for shard/caching paths |
| `xunit` / `xunit.runner.visualstudio` / `Microsoft.NET.Test.Sdk` | 2.9.3 / 3.1.x / 18.x | Test framework. xUnit's per-test isolation suits protocol and persistence tests |
| `Shouldly` | 4.3.0 | Readable assertions. Chosen over FluentAssertions, which moved to a commercial licence at v8 |
| `Microsoft.SourceLink.GitHub` | 8.x | Debuggable production builds |

**Deliberately excluded:** any Entity Framework package, AutoMapper (commercial from v15;
hand-written mapping is clearer for ~30 DTOs anyway), and any "SMTP server in a box"
library — the SMTP engine is the product.

---

## 23. Domain entity list

### Aggregate roots

| Aggregate | Guards |
|---|---|
| `MailDomain` | Name immutability, hostname validity, enable/disable, catch-all, quota policy, DKIM selector assignment |
| `Mailbox` | Address uniqueness within its domain, quota, enable/disable, access flags, credential lifecycle |
| `Alias` | Source/target validity, no self-reference, expansion-depth limits |
| `StoredMessage` | Folder membership, UID allocation, flag transitions, size and hash immutability |
| `OutboundQueueItem` | Status transition legality, attempt counting, lease ownership |
| `DkimKey` | Selector uniqueness, state machine (Generated → Published → Active → Retired) |
| `CertificateBinding` | Hostname/purpose uniqueness, source, renewal policy |
| `CertificateAuthorityAccount` | Directory URL, key reference, ToS acceptance record |
| `BackupRecord` | Integrity metadata, retention |
| `ServerConfiguration` | Singleton aggregate for mutable runtime settings |
| `AdminAccount` | Master password hash, recovery key, lockout state (Milestone 2) |

### Supporting entities

`MailboxCredential`, `MailboxFolder`, `DeliveryAttempt`, `DnsCheck`, `SecurityEvent`,
`BlockedIp`, `AllowedIp`, `QuarantineItem`, `DmarcReport`, `DmarcReportRecord`,
`TlsReport`, `TlsReportPolicy`, `AuditRecord`, `MetricSample`, `SmtpSessionRecord`,
`UnsubscribeToken`, `SmartHost`, `MaintenanceWindow`.

### Value objects

`DomainName` (IDNA/punycode aware — also used for hostnames, since a mail hostname is a
fully-qualified domain name and a second near-identical type would only invite them to drift),
`EmailAddress`, `IpAddressValue`,
`DkimSelector`, `CertificateThumbprint`, `MessageId`, `QuotaBytes`, `MessageSize`,
`Sha256Hash`, `RetryScheduleEntry`, `EnhancedStatusCode`, `AuditDescriptor`,
and strongly-typed ids: `DomainId`, `MailboxId`, `AliasId`, `QueueId`, `StoredMessageId`,
`DkimKeyId`, `CertificateId`, `AuditId`.

Strongly-typed ids exist because `Task DeleteAsync(Guid id)` accepting a `MailboxId` where
a `DomainId` was meant is a data-loss bug that the compiler should catch. They are readonly
record structs, so there is no allocation cost.

### Enums

`DomainStatus`, `MailboxStatus`, `QueueStatus`, `DeliveryOutcome`, `FailureClassification`,
`DkimKeyStatus`, `CertificateSource`, `CertificateStatus`, `TlsMode`, `SmtpListenerRole`,
`AuthMechanism`, `MaintenanceMode`, `HealthState`, `AdminPermission`, `SpfResult`,
`DkimResult`, `DmarcResult`, `DmarcPolicy`, `AlignmentMode`, `MessageDisposition`.

---

## 24. Repository and query abstractions

Two families, deliberately separated:

**Repositories** load and persist aggregates. They return domain objects, participate in
transactions, and are used by commands.

```csharp
public interface IDomainRepository
{
    Task<MailDomain?> GetByIdAsync(DomainId id, CancellationToken ct);
    Task<MailDomain?> GetByNameAsync(DomainName name, CancellationToken ct);
    Task<bool> ExistsAsync(DomainName name, CancellationToken ct);
    Task<IReadOnlyList<MailDomain>> GetAllAsync(CancellationToken ct);
    Task AddAsync(MailDomain domain, CancellationToken ct);
    Task UpdateAsync(MailDomain domain, CancellationToken ct);
    Task RemoveAsync(DomainId id, CancellationToken ct);
}
```

**Query services** serve read models. They return flat DTOs shaped for a screen or an API,
run hand-tuned SQL with paging and filtering, and never materialize an aggregate.

```csharp
public interface IMailQueueQueries
{
    Task<PagedResult<QueueItemDto>> SearchAsync(QueueSearchRequest r, CancellationToken ct);
    Task<QueueItemDetailDto?> GetDetailAsync(QueueId id, CancellationToken ct);
    Task<IReadOnlyList<DeliveryTraceEntryDto>> GetTraceAsync(QueueId id, CancellationToken ct);
    Task<QueueStatisticsDto> GetStatisticsAsync(CancellationToken ct);
}
```

Forcing a 10 000-row queue grid through an aggregate repository would be slow and pointless;
forcing a state transition through a flat DTO would bypass invariants. Keeping both and
being explicit about which is which is the whole point of CQRS here.

### Avoiding duplicated SQL across two providers

Repository implementations are written **once**, in `MailServer.Infrastructure/Persistence`,
against an `ISqlDialect` that supplies the provider-specific fragments:

```csharp
public interface ISqlDialect
{
    string Name { get; }
    bool RequiresSerializedWrites { get; }          // true for SQLite only
    string QuoteIdentifier(string identifier);
    string LimitClause(int take, int skip);         // LIMIT/OFFSET vs OFFSET/FETCH
    string UtcNowExpression { get; }
    string ClaimQueueItemsSql { get; }              // RETURNING vs OUTPUT+READPAST
    bool IsTransient(DbException exception);
    string MigrationsResourcePrefix { get; }
}
```

`MailServer.Persistence.Sqlite` and `MailServer.Persistence.SqlServer` supply the dialect,
the connection factory, the migration scripts and a single DI registration extension. Only
genuinely divergent SQL is written twice, and the divergence is enumerable and testable.

---

## 25. Directory structure

```text
iMailServer/
├── MailServer.sln
├── Directory.Build.props            # shared compiler settings, analyzers, nullable
├── Directory.Packages.props         # central package management (one version, solution-wide)
├── NuGet.config                     # nuget.org only
├── .editorconfig
├── README.md
├── build/
│   └── (CI scripts, packaging)
├── docs/
│   ├── Architecture.md              # this document
│   ├── CleanArchitecture.md   CQRS.md         Persistence.md
│   ├── Sqlite.md              SqlServer.md    WindowsServer.md
│   ├── Installation.md        SMTP.md         IMAP.md
│   ├── DNS.md                 DKIM.md         SPF.md
│   ├── DMARC.md               TLS.md          Certificates.md
│   ├── LetsEncrypt.md         Security.md     Deliverability.md
│   ├── BackupRestore.md       Troubleshooting.md
│   └── Standards.md                 # per-standard status: Implemented/Partial/Planned
├── src/
│   ├── MailServer.Domain/           # Entities, ValueObjects, Enums, Events, Exceptions, Policies
│   ├── MailServer.Application/      # Abstractions, Behaviors, Commands, Queries, Handlers,
│   │                                #   Validators, DTOs, Security, Mail, Domains, Mailboxes,
│   │                                #   Queue, Certificates, Deliverability, Monitoring
│   ├── MailServer.Infrastructure/   # Persistence, Storage, Security, Cryptography,
│   │                                #   Certificates, Dns, Logging, Networking, Time, System
│   ├── MailServer.Persistence.Sqlite/
│   ├── MailServer.Persistence.SqlServer/
│   ├── MailServer.Ipc/              # wire contracts + framing + named-pipe client/server
│   ├── MailServer.Protocols.Common/ # bounded readers, TLS helpers, transcripts  (M6)
│   ├── MailServer.Protocols.Smtp/   (M6-M8)   MailServer.Protocols.Imap/   (M10)
│   ├── MailServer.Protocols.Pop3/   (M10)     MailServer.Deliverability/   (M11)
│   ├── MailServer.Filtering/        (M12)     MailServer.WebEndpoints/     (M4)
│   ├── MailServer.Service/          # Windows Service host — the real server
│   ├── MailServer.Admin/            # WPF administration application
│   └── MailServer.Installer/        # WiX packaging (M13)
└── tests/
    ├── MailServer.Domain.Tests/          MailServer.Application.Tests/
    ├── MailServer.Infrastructure.Tests/  MailServer.Persistence.Tests/
    ├── MailServer.Ipc.Tests/             MailServer.Smtp.Tests/        (M6)
    ├── MailServer.Imap.Tests/      (M10) MailServer.SecurityTests/     (M6)
    ├── MailServer.Deliverability.Tests/  (M11)
    └── MailServer.IntegrationTests/      (M6)
```

Projects annotated with a milestone are created **in that milestone**, with real code and
real tests. Empty placeholder projects are not created, because a solution full of empty
assemblies is indistinguishable from a demonstration and provides no compile-time value.

---

## 26. Configuration model

Strongly-typed, validated at startup, immutable at runtime. Sources in precedence order:
`appsettings.json` → `appsettings.{Environment}.json` → `ProgramData` machine config →
environment variables (`AETHERMAIL_`) → command line. **Secrets never live in JSON**; they
live in the DPAPI-protected secret store and configuration holds only a reference.

```jsonc
{
  "MailServer": {
    "Server": {
      "Hostname": "mail.example.com",     // EHLO identity; must be a real FQDN with PTR
      "PublicIpAddress": "203.0.113.10",
      "ProductName": "AetherMail Server"
    },
    "Database": {
      "Provider": "Sqlite",               // Sqlite | SqlServer
      "Sqlite":    { "DataSource": "C:\\ProgramData\\AetherMail\\Data\\mailserver.db",
                     "BusyTimeoutMs": 5000, "JournalMode": "WAL" },
      "SqlServer": { "ConnectionStringSecretName": "Db.SqlServer.ConnectionString",
                     "CommandTimeoutSeconds": 30, "MaxRetryAttempts": 5 },
      "Migrations": { "RunOnStartup": true, "BackupBeforeDestructive": true }
    },
    "Storage": {
      "DataRoot": "C:\\ProgramData\\AetherMail\\Data",
      "MaxMessageSizeBytes": 36700160,    // 35 MiB
      "MinimumFreeDiskBytes": 2147483648
    },
    "Listeners": {
      "SmtpInbound":     { "Enabled": true,  "Port": 25,  "TlsMode": "StartTls" },
      "SmtpSubmission":  { "Enabled": true,  "Port": 587, "TlsMode": "StartTlsRequired" },
      "SmtpImplicitTls": { "Enabled": true,  "Port": 465, "TlsMode": "Implicit" },
      "Imap":            { "Enabled": true,  "Port": 993, "TlsMode": "Implicit" },
      "Pop3":            { "Enabled": false, "Port": 995, "TlsMode": "Implicit" },
      "Http":            { "Enabled": true,  "Port": 80  },
      "Https":           { "Enabled": true,  "Port": 443 }
    },
    "Tls": {
      "MinimumProtocol": "Tls12",
      "PreferredCertificateSource": "LetsEncrypt",
      "SelfSigned": { "KeySizeBits": 3072, "ValidityYears": 1 }
    },
    "Acme": {
      "Enabled": false,
      "Directory": "https://acme-v02.api.letsencrypt.org/directory",
      "UseStagingForFirstIssue": true,
      "ContactEmail": "postmaster@example.com",
      "RenewWhenDaysRemainingBelow": 30,
      "ChallengeType": "Http01"           // Http01 | Dns01 | ManualDns01
    },
    "Delivery": {
      "Mode": "DirectMx",                 // DirectMx | SmartHost
      "MaxConcurrentDeliveries": 32,
      "PerDomainMaxConcurrency": 4,
      "RetryScheduleMinutes": [1, 5, 15, 30, 60, 120, 240, 480],
      "MaxLifetimeHours": 120,
      "DelayWarningAfterHours": 4,
      "SmartHost": { "Host": "", "Port": 587, "TlsMode": "StartTlsRequired",
                     "Username": "", "PasswordSecretName": "" }
    },
    "Limits": {
      "MaxRecipientsPerMessage": 100,
      "MaxConcurrentConnectionsPerIp": 10,
      "MaxConcurrentConnectionsTotal": 500,
      "SmtpCommandTimeoutSeconds": 300,
      "SmtpSessionTimeoutSeconds": 600,
      "MaxSmtpLineBytes": 4096,
      "MaxHeaderBytes": 262144,
      "MaxMimeDepth": 20,
      "MaxAuthAttemptsPerSession": 3
    },
    "Ipc": {
      "PipeName": "AetherMail.Admin",
      "MaxFrameBytes": 4194304,
      "RequestTimeoutSeconds": 60,
      "MaxConcurrentConnections": 8
    },
    "Security": {
      "SecretProtection": "Dpapi",        // Dpapi | Development (non-production only)
      "AdminLockoutThreshold": 5,
      "AdminLockoutMinutes": 15,
      "AutoLockMinutes": 10
    },
    "Logging": {
      "Directory": "C:\\ProgramData\\AetherMail\\Data\\Logs",
      "RetainedFileCount": 31,
      "MinimumLevel": "Information",
      "SessionTranscripts": { "Enabled": true, "RetentionDays": 7 }
    },
    "Maintenance": { "Mode": "Normal" }
  }
}
```

Each section binds to an options record validated by a `IValidateOptions<T>` implementation
at startup. Invalid configuration prevents the service from starting rather than producing
a subtly wrong server — a mail server with a wrong `Hostname` sends mail that fails FCrDNS
checks everywhere, which is far worse than a service that refuses to start with a clear
message.

---

## 27. Development milestones

| # | Milestone | Delivers | Exit criteria |
|---|---|---|---|
| **1** | **Core Foundation** | Solution, Clean Architecture, MediatR + all pipeline behaviors, configuration, logging, both connection factories, migration runner, repository/query abstractions, transaction manager, Windows Service shell, WPF shell, secure IPC, one vertical slice (Domains) proving the stack end to end | Solution compiles; all tests green; service starts, migrates, serves IPC; WPF lists and creates domains through IPC |
| 2 | Security & Administration | Master password (Argon2id), DPAPI secret store, recovery key, admin sessions, lockout, auto-lock, audit log, per-command authorization | Admin auth enforced on every IPC command; audit rows written; security tests green |
| 3 | Certificate Infrastructure | `ICertificateManager`, self-signed generator, Windows cert store integration, bindings, status model, hot-reload plumbing | Generate a self-signed cert with correct SANs/EKU; hot-swap without restart |
| 4 | ACME / Let's Encrypt | ACME account, HTTP-01, DNS-01 abstraction + manual fallback, issuance, install, renewal service, Kestrel endpoints | Staging certificate issued and renewed end to end |
| 5 | Domain Administration | Mailboxes, aliases, credentials, quotas, folders, special addresses | Full CRUD through IPC + WPF; quota enforcement tested |
| 6 | SMTP Inbound | Listener, state machine, ESMTP verbs, STARTTLS, local delivery, **relay protection** | Open-relay test suite green; inbound mail from a real MTA delivered |
| 7 | SMTP Submission | 587/465, AUTH PLAIN/LOGIN over TLS, submission policy, per-mailbox rate limits | A real mail client sends through the server — **met**: Python's `smtplib` authenticates and submits on both ports; see `docs/SMTP.md` |
| 8 | Outbound MTA | MX lookup, delivery client, queue, leasing, retry, per-domain throttling, DSN | Mail delivered to a live external provider; bounces generated correctly |
| 9 | Mail Authentication | DKIM signing/verification, SPF, DMARC, alignment, ARC groundwork | Google/Microsoft report SPF+DKIM+DMARC pass |
| 10 | IMAP (+ optional POP3) | Full mailbox access, UID correctness, IDLE, SPECIAL-USE | Thunderbird/Outlook/Apple Mail interoperate without mail loss |
| 11 | Deliverability | DNS wizard, PTR/FCrDNS testing, MTA-STS, TLS-RPT, certificate health, delivery test, header analyzer, reputation interfaces, scoring | Full readiness report renders with evidence for every check |
| 12 | Filtering | Rate limits, anti-spam pipeline, quarantine, malware interface, attachment policy | Quarantine round-trip; resource-exhaustion tests green |
| 13 | Production Hardening | WiX installer, firewall automation, service recovery, backup/restore, SQLite→SQL Server migration, monitoring, full docs | Clean install → first-run wizard → sending and receiving production mail |

Milestone 1 is the subject of the accompanying implementation.

---

## 28. Major risks

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| 1 | **MediatR licensing.** v13+ is commercial; only ≤12.5.0 is Apache-2.0 | Forced upgrade or licence purchase later | Pin 12.5.0. Handlers depend on `IRequestHandler`, and hosts depend on `ISender` — both trivially replaceable. A ~150-line in-house dispatcher could replace MediatR in a day if needed. **Recommend evaluating this before Milestone 5** |
| 2 | **Port 25 is blocked on most clouds/ISPs** (Azure blocks outbound 25 on almost all subscriptions; AWS/GCP require a request; most residential ISPs block it permanently) | The server cannot deliver mail directly at all | Detect at setup and continuously; explain plainly; offer smarthost relay as a first-class supported mode, not an afterthought |
| 3 | **IP reputation is earned, not configured.** A brand-new IP is untrusted by Gmail/Microsoft regardless of perfect SPF/DKIM/DMARC | Mail lands in spam despite a 100/100 readiness score | Never promise inbox placement. Document warm-up. Report readiness, not outcomes |
| 4 | **Microsoft 365 / Outlook.com is the hardest receiver.** It throttles unknown senders aggressively and its delisting process is manual | Sustained deferrals to a major provider | Per-domain throttling that *backs off*; surface SNDS/JMRP guidance; never retry-storm |
| 5 | **IMAP UID correctness bugs cause silent mail loss** in clients | Catastrophic, hard to detect, destroys trust | UID allocation inside the insert transaction; unique constraints; a dedicated UID/UIDVALIDITY test suite; test against three real clients |
| 6 | **SQLite write contention** under concurrent queue processing | Latency spikes, `SQLITE_BUSY` errors | WAL, busy timeout, single in-process write gate, short transactions, and an honest recommendation to move to SQL Server |
| 7 | **Two-resource consistency** (filesystem + database) with no distributed transaction | Orphaned blobs or dangling references | Strict store-then-commit ordering; always fail toward orphaned blobs; housekeeping reaper |
| 8 | **ACME rate limits** burned during setup troubleshooting | Cannot obtain a certificate for up to a week | Staging by default on first issuance; local rate-limit accounting; DNS/port pre-flight before contacting the CA |
| 9 | **Certificate renewal failure** going unnoticed | Total TLS outage | Escalating alerts from 30 days out; never downgrade to self-signed; renewal health is part of the deliverability score |
| 10 | **DPAPI is machine-scoped.** Restoring a backup onto a new machine cannot decrypt secrets | Unrecoverable DKIM/ACME keys after hardware migration | Backups include secrets re-wrapped under a passphrase-derived key with an explicit, documented export step; restore-to-new-machine is an exercised, tested procedure |
| 11 | **Scope.** This is a genuinely large system; thirteen milestones is optimistic for a small team | Half-finished subsystems, worst of all outcomes | Milestone exit criteria are binary and testable. `docs/Standards.md` never marks anything Implemented without passing tests |
| 12 | **Windows-only verification constraints.** DPAPI, Windows ACLs, cert store and the SCM cannot be exercised on Linux CI | Windows-specific bugs found late | Windows-hosted CI from Milestone 2 onward; platform-specific code behind interfaces with fakes for cross-platform tests |
| 13 | **Being a spam source.** A compromised mailbox or a policy bug turns the server into an abuse origin | IP blacklisting, provider blocking, legal exposure | Per-mailbox send limits, outbound anomaly detection, abuse@/postmaster@ handling, no IP rotation, no evasion features |

---

## 29. Difficult protocol areas

These are the parts where "almost right" is indistinguishable from broken, and where extra
test investment is budgeted up front.

1. **Dot-stuffing and the `DATA` terminator.** A leading `.` on a line must be unstuffed on
   receipt and stuffed on send. A message whose body legitimately contains `\r\n.\r\n` must
   not truncate. Bare `\n` line endings from sloppy clients must be normalized without
   corrupting content. This is tested with adversarial payloads.
2. **`PIPELINING` + `STARTTLS`.** Commands may arrive batched. After `STARTTLS`, every
   buffered plaintext byte must be discarded (§6). Getting this wrong is a CVE.
3. **`BDAT`/`CHUNKING`.** Exact byte counting, `LAST` semantics, interaction with
   `PIPELINING`, and error recovery mid-chunk.
4. **`SMTPUTF8` and IDNA.** Punycode for the transport, UTF-8 for display; downgrade rules
   when the remote lacks `SMTPUTF8`; never silently mangle an address. Round-trip fidelity
   is tested in both directions.
5. **MIME edge cases.** Nested multiparts, malformed boundaries, RFC 2047 encoded words
   with mixed charsets, `format=flowed`, 8-bit content in a 7-bit path. Delegated to MimeKit
   precisely because these are where hand-rolled parsers fail.
6. **DKIM canonicalization.** Relaxed body canonicalization's trailing-whitespace and
   trailing-empty-line rules are unforgiving: one byte wrong and every signature fails
   verification everywhere. Tested against RFC 6376 vectors plus real signed mail.
7. **DMARC organizational-domain resolution.** Requires a current Public Suffix List;
   `co.uk` vs `example.co.uk` errors silently invert alignment results.
8. **SPF macro expansion and lookup limits.** Macros are obscure and rarely implemented
   correctly; the 10-lookup and 2-void-lookup limits must produce `permerror`, not partial
   evaluation.
9. **IMAP literals, `LITERAL+`, and sequence-set arithmetic.** `{n+}` non-synchronizing
   literals let a client push arbitrary bytes before the server can refuse — hard caps are
   mandatory. Sequence sets like `1,3:5,*:8` and `UID` variants are a classic bug farm.
10. **IMAP `SEARCH` charset and `FETCH BODY[…]` part addressing.** Partial fetches
    (`BODY[1.2.HEADER]<0.2048>`) must map exactly onto MIME structure.
11. **`EXPUNGE` response sequencing.** Untagged `EXPUNGE` at the wrong moment, or in the
    wrong order, makes clients delete the wrong messages.
12. **TLS certificate selection and SNI** across five listener types with hot reload, while
    remaining compatible with MTAs that send no SNI at all.
13. **MX selection, fallback and failure classification.** Distinguishing temporary from
    permanent failure correctly is the difference between lost mail and infinite retries.
14. **Bounce-loop prevention** with null reverse paths, `Auto-Submitted`, and DSN
    generation that is itself never bounced.
15. **Graceful shutdown mid-`DATA`** without duplicating or losing a message.

---

## 30. Recommended changes before development starts

These are my recommendations as architect. Each has a default that I proceed with unless
directed otherwise.

1. **Pin MediatR to 12.5.0 and keep it replaceable** — or drop it now. The brief mandates
   MediatR, so I proceed with 12.5.0 (Apache-2.0) and keep the abstraction seam thin.
   *Decision needed before Milestone 5, not now.*
2. **Add `MailServer.Ipc` as an explicit project.** The brief's structure has no home for
   the IPC contract. It needs one, because it is a versioned compatibility surface between
   two independently upgradable processes. **Proceeding with this addition.**
3. **Treat `MailServer.WebEndpoints` as a library hosted inside the service**, not a
   separate process. One process, one configuration, one certificate provider, one thing to
   install and secure. **Proceeding.**
4. **Do not create empty placeholder projects** for milestones 6–13. They add no
   compile-time value and make the solution look finished when it is not. Projects are
   created in the milestone that fills them. **Proceeding.**
5. **Write repositories once against `ISqlDialect`** rather than twice per provider.
   Duplicated SQL across two providers is where drift and data-corruption bugs breed.
   **Proceeding.**
6. **Move Argon2id to Milestone 1's design but Milestone 2's implementation**, and ship
   Milestone 1 with authorization *plumbing* wired and a deny-by-default policy, so that
   Milestone 2 fills in identity rather than retrofitting enforcement. **Proceeding.**
7. **Add an eighth pipeline behavior for correlation** (the brief lists seven concerns).
   Without an id assigned at the very top, message trace and audit cannot be joined.
   **Proceeding.**
8. **Reconsider POP3.** It is genuinely harmful alongside IMAP on the same mailbox
   (destructive reads). *Recommendation:* keep it implemented but disabled, with an explicit
   warning at enable time. **Proceeding as specified in the brief.**
9. **Budget a Windows CI runner from Milestone 2.** DPAPI, ACLs, the certificate store and
   the SCM cannot be verified on Linux. *This needs a decision from you* — it affects
   infrastructure cost.
10. **Decide the deployment target early.** If this will run on Azure VMs, outbound port 25
    is blocked with no exception process for most subscriptions, which makes smarthost mode
    mandatory rather than optional. *This needs an answer from you* and changes what
    Milestone 8 must prioritize.
11. **Consider Ed25519 DKIM (RFC 8463) as a secondary signature** from Milestone 9. Cheap
    to add alongside RSA, and increasingly recognized. *Recommendation only.*
12. **Rename the delivery-retry configuration from a fixed list to a policy object** so
    per-destination schedules become possible without a schema change. **Proceeding.**

Nothing in items 9 and 10 blocks Milestone 1, so implementation begins now.

---

## Addendum — decisions taken during Milestone 2

The baseline above stands. Four decisions were made or changed while implementing the security
layer, and they are recorded here rather than edited into the sections above, so the difference
between what was designed and what was learned stays visible.

### A2.1 — Sessions replace Windows identity as the authorization principal

§21 proposed the pipe ACL as the primary control, with the caller's Windows identity mapped to
a permission set. That is now defence in depth only. `ResolveCaller` returns
`AdminPermission.None`, and permissions come exclusively from a session issued by a successful
sign-in.

The ACL answers "may this process open the pipe"; it cannot answer "is a human present who
knows the master password". Treating the first as an answer to the second would mean any
process running elevated — including a compromised unrelated tool — could reconfigure mail
routing for every hosted domain.

IPC protocol version 2 therefore refuses version 1 outright, rather than negotiating down. A v1
client is by definition one that expects to administer the server without signing in, and a
compatibility path for it would be a documented bypass.

### A2.2 — Security events are buffered, audit records are transactional

§21 treated the audit trail and the security event log as one concern. They are not, and the
distinction is about consistency direction:

- An audit record must **not** survive the rollback of the change it describes. It joins the
  request's transaction.
- A security event **must** survive the rollback of the operation it describes — a failed
  sign-in is exactly the case where the operation is rejected and the record must persist. It
  is buffered during the request and flushed after commit or rollback.

This was forced by a defect, not foreseen. Writing security events on a second connection
inside an open write transaction deadlocked against SQLite's single-writer lock: each event
stalled for the full busy timeout and was then silently dropped. The design comments in
`ITransactionManager` had warned about exactly this; the code did it anyway, and the tests
caught it.

### A2.3 — Authentication is not transactional

`AuthenticateCommand` deliberately carries no `ITransactionalRequest` marker. A failed attempt
increments the persisted failure counter and then throws, and `TransactionBehavior` rolls back
on exception — so a transaction would discard the increment that drives lockout, leaving
brute-force protection inert while appearing correct everywhere an operator would look.

This too was a real defect caught by tests rather than by review, which is the argument for the
security suite existing at all. A structural test now asserts the marker's absence, because a
behavioural test alone would catch the regression without explaining it.

Nothing is lost by dropping the transaction: every path performs at most one row update, the
session lives in memory, and security events are flushed out of band per A2.2.

### A2.4 — The recovery key is the only recovery path

No support backdoor, no file-deletion reset, no vendor override. 125 bits of entropy, stored
Argon2id-hashed, single-use, and it bypasses lockout so that an attacker who can trigger a
lockout cannot thereby deny the administrator their own recovery path.

If both the password and the key are lost, the database must be recreated. That is the correct
trade: any recovery mechanism weaker than the credential it recovers *is* the credential, and
would be the thing actually attacked.

---

## Addendum — decisions taken during Milestone 3

§14 stands. Three decisions were made or refined while building the certificate subsystem.

### A3.1 — A subjectAltName entry is not a hostname

§14 assumed certificate coverage could be expressed with `DomainName`. It cannot:
`*.example.com` is a legal, common SAN and is not a domain name at all — no mail is addressed to
it and no DNS lookup resolves it.

Forcing it through `DomainName` would mean either rejecting real certificates or loosening the
type that mail domains, MX hostnames and EHLO names all depend on, so that `*.example.com`
became an acceptable mail domain. `CertificateSubjectName` is therefore a separate value object,
and the relationship runs in the useful direction: a subject name *matches* a hostname.
Hostnames stay strictly validated; patterns live in the new type.

Matching follows RFC 6125 §6.4.3 strictly, and the strictness is deliberately asymmetric.
Erring permissive is the harmful direction: it makes the server report a hostname as covered
while every connecting client rejects it, so the fault surfaces as user reports rather than as
anything visible here.

### A3.2 — Hot reload must wrap the transaction, not sit inside it

§14 specified the atomic snapshot swap and was right about it. What it did not anticipate is
*when* the swap can be performed.

A handler that changes a binding runs inside the request's transaction, so the rows it wrote are
not visible on the fresh connection the provider uses to rebuild its snapshot. Reloading there
rebuilds from the state *before* the change and then logs success — a hot swap that silently
does not swap, which is a worse failure than one that fails loudly, because nothing about it
looks wrong.

This produced the ninth pipeline behavior. `TlsReloadBehavior` is registered immediately outside
`TransactionBehavior`, so its post-`next()` code runs after commit. Handlers signal intent via
`ITlsReloadCoordinator`; the behavior performs the reload once, and only on success.

The shape is the same as the Milestone 2 security-event buffering (A2.2), and for the same
underlying reason: **work that must happen around a transaction rather than inside it is
signalled during the request and performed by a pipeline behavior once the transaction's fate is
known.** That is now a pattern in this codebase rather than a one-off.

A related consequence of the snapshot design: the superseded snapshot's certificates cannot be
disposed at the moment of the swap. A handshake that read the old reference microseconds earlier
is still using them, and disposing an `X509Certificate2` out from under an in-flight handshake
throws inside the TLS stack. They are held for a five-minute rollback window.

### A3.3 — Invariants that span rows belong in the database

"At most one default binding" is enforced by a unique filtered index, not by application code.

That choice has a consequence worth recording, because it caused a real defect: the old default
must be cleared **before** the new row claims the flag, or the constraint rejects the write. The
natural writing order — insert the new default, then clear the others — fails, and it fails only
when a *second* certificate is made the default, never the first. It passed every manual check
and was caught by a test.

The alternative, enforcing it in code, would have had no such failure and a worse property: a
window in which two bindings are default, or none. None is the dangerous one — a handshake
without SNI would have no certificate to present, and the mail that fails is inbound mail
reported by the sender rather than by this server.

---

## Addendum — decisions taken during Milestone 4

§15 stands. Four things were decided or corrected while building it.

### A4.1 — Certes is accepted with a stated dependency risk

§22 named Certes and it remains the right call: hand-implementing ACME's JWS signing, nonce
handling and key-authorisation digests is an unnecessary cryptographic risk in the one component
that touches the account key.

What was not visible in §22 is that Certes 3.0.4 (January 2023, the last release) depends on
**Portable.BouncyCastle 1.9.0** — the legacy BouncyCastle package, superseded by
`BouncyCastle.Cryptography` and unmaintained. It carries no advisories and is not formally
deprecated, and it was verified working on .NET 10. It is nonetheless an unmaintained transitive
dependency in a security-sensitive path, and is tracked as a risk.

The `IAcmeClient` port exists partly for this reason: replacing Certes is one file plus its
factory, not a rewrite of the issuance logic.

### A4.2 — The source a certificate is stored under decides whether it renews

Issuance originally stored its result through the certificate manager's operator-import path,
on the reasonable-sounding grounds that the storage is identical either way.

It is not identical, because the recorded **source** is what the renewal loop filters on. An
ACME certificate stored as `ImportedPfx` is one the aggregate correctly refuses to auto-renew —
this server cannot reissue somebody else's imported certificate — so every certificate obtained
automatically would have expired without a single renewal attempt, while the renewal loop ran
every twelve hours and found nothing to do.

This is the third defect of the same shape in four milestones: Milestone 2's lockout counter
rolled back by its own transaction, Milestone 3's default-binding write ordering, and now this.
All three were code that looked correct, passed review, and did nothing. All three were caught
by a test written to assert the *outcome* rather than the mechanism. That is worth stating as a
practice: **for anything that is supposed to happen automatically, assert that it happened, not
that the code which would cause it exists.**

### A4.3 — A directive parser must not match prose

The migration runner decided a script was destructive by searching for `-- @Destructive`
anywhere in the file. The natural comment at the top of an additive migration is "this is not
marked @Destructive", and whether that tripped the check depended on where the sentence happened
to wrap.

Migrations 0002 and 0003 escaped by luck. 0004 wrapped differently, was classified destructive,
refused to apply, and took every database-backed test in the solution with it — 94 failures from
a comment.

Directives are now matched as a whole comment line. A rule that holds because of where a
sentence breaks is not a rule.

### A4.4 — Wildcards are refused rather than half-supported

A wildcard certificate can be obtained: DNS-01 is implemented and is the challenge wildcards
need. It could not then be *presented*, because `TlsCertificateProvider` selects by exact SNI
hostname, so a certificate bound to `*.example.com` would never be chosen for any name it
covers.

Issuing one would spend real, rate-limited quota on something the server cannot serve. The
request is therefore refused, with a message that names that reason rather than a generic
validation error — an operator told "not a valid hostname" would check the spelling of something
that is spelled correctly.

Wildcard support is a change to the handshake path, not to ACME, and belongs with whichever
milestone makes binding lookup wildcard-aware.

---

## Addendum — decisions taken during Milestone 5

§23 stands. Four decisions are worth recording, three of them trades rather than discoveries.

### A5.1 — Challenge-response SMTP AUTH is refused, and this is the reason

CRAM-MD5 and DIGEST-MD5 require the server to hold something it can compute a challenge
response from — in practice the password, or a reversible transformation of it. A mail server
storing recoverable mailbox passwords turns one database read into every user's password, and
those users have reused them elsewhere.

The trade is stated rather than quietly made. AUTH PLAIN and AUTH LOGIN send the password to a
server that verifies it against an Argon2id hash and discards it, which is strictly better
given that rule 105 already forbids offering AUTH without TLS. What is given up is
interoperability with a small number of old clients configured for CRAM-MD5, and the honest
framing is that those clients are asking for something no server should agree to.

### A5.2 — Suspended and Disabled are different states, and the difference is what leaks

A **disabled** mailbox rejects mail and refuses logins. A **suspended** one keeps accepting
mail and refuses logins only.

Suspension is the state for someone who has left, an account under investigation, or one whose
password may be compromised. Rejecting mail in that state announces the suspension to every
sender — which for a compromised account is precisely the signal not to broadcast, and for a
departed employee tells every correspondent something the organisation may not have said yet.
Accepting mail costs storage and loses nothing.

### A5.3 — Alias cycles are refused at creation, not merely survived at delivery

`AliasExpansionPolicy` is bounded in depth and breadth, so a cycle terminates and a fan-out
cannot amplify. That is the backstop and it runs on the SMTP path for every message.

It is not sufficient on its own, because the way it survives a cycle is by silently dropping
recipients. The operator who built the cycle is the one person who can fix it, and the moment
they can is while they are looking at the alias. So `CreateAlias` and `UpdateAlias` expand the
graph *as it would be* and refuse a change that makes expansion unbounded or empty.

Two limits rather than one, and they catch different things: depth stops a cycle, breadth stops
amplification. One message to one address becoming several hundred deliveries is a
resource-exhaustion problem and, where targets are external, an outbound reputation problem — a
server emitting a burst of near-identical messages looks exactly like a compromised one.

### A5.4 — "Zero means inherit" has one sharp edge, and it is documented rather than removed

A mailbox quota of zero means "inherit the domain default", matching the schema written in
Milestone 1. The consequence is that a mailbox cannot be *explicitly* unlimited while its
domain has a quota.

A nullable column would express both, and would also mean every read path distinguishing null
from zero — in delivery, in the admin UI, in the grid's percentage calculation. The encoding
stays; the edge is asserted in a test named for it, so an operator who meets it finds it
documented rather than surprising.

The related decision: a quota **may** be set below current usage. Refusing would leave an
operator unable to act on a mailbox that is already too large, which is exactly when they most
need to.

---

---

## Addendum — decisions taken during Milestone 6

§23 stands. Six decisions are worth recording; three of them were forced by bugs that only
running the server exposed.

### A6.1 — The end-of-DATA marker is decided on raw octets, before anything else touches them

`SmtpDataDecoder` does three jobs — find the end of the message, normalise line endings,
unstuff the transparency dot — and **the order is the security property**, not an
implementation detail.

Normalising first would rewrite a body containing `"\n.\n"` into `"\r\n.\r\n"`, and the
scan would then find a terminator the sending server never sent. The message truncates there
and the remainder — attacker-chosen octets, including a fresh `MAIL FROM` — reaches the command
parser. That is SMTP smuggling (2023), and the defence is exactly this ordering: only the
five-octet sequence `CRLF "." CRLF` ends a message, decided before normalisation exists.

Unstuffing cannot reintroduce the problem because it only ever *removes* a dot; it can never
manufacture a terminator.

### A6.2 — An over-long command line poisons the session rather than resynchronising

`SmtpLineReader` latches on `LineTooLong` and stays there. The obvious recovery — skip to the
next CRLF and carry on — hands the tail of an over-long line to the command parser, and that
tail is attacker-chosen text. It is the same command-injection shape as the STARTTLS bug
reached from a different direction. The only correct response is 500 and close.

### A6.3 — Pipelining across STARTTLS closes the connection rather than being silently dropped

RFC 3207 §4 requires discarding what arrived before the handshake, and discarding silently
would satisfy it. This server refuses the connection and logs it instead.

No legitimate client pipelines across STARTTLS — the RFC forbids it precisely because those
octets would execute inside the tunnel with the authority the real client later establishes. A
peer doing it is either broken in a way its operator needs to know about, or attacking. Both
are worth a log line and neither is worth continuing.

### A6.4 — Submission listeners fail closed, and are therefore off by default

`RequiresAuthentication` is **not** conditioned on whether SASL is implemented. While
authentication is unavailable a submission listener refuses every sender, which is the safe
failure; the alternative is a listener that quietly accepts unauthenticated mail because the
means to authenticate had not been written yet.

Because a port that is advertised and unusable is worse than one that is absent, both
submission listeners ship disabled. They are enabled with SASL in Milestone 7.

### A6.5 — Three bugs of the A4.2 shape, two of which only running the server found

The pattern recorded in A4.2 — *code that looks correct, passes review, and silently does
nothing* — produced three more instances here. All three are worth naming because the first two
had passing tests around them.

| Bug | Why the tests missed it | What now catches it |
|---|---|---|
| `SmtpSessionContext` cleared its recipient list **in place** while delivery still held a view of it — a message delivered to nobody, with no error anywhere | The unit tests read `Recipients` before the reset; only a socket test held the snapshot across it | The list is **replaced** on reset, so snapshots already taken stay valid |
| `SmtpDirectory` reported a mailbox full whenever its quota was smaller than the server-wide message size limit — which is most mailboxes, including empty ones | `SmtpDirectory` had no tests at all. Every other layer did | 23 directory tests; the old check fails seven of them |
| `SmtpConnectionHandler` was resolved from the root provider despite being scoped | No test started the real host | The service starts as part of milestone verification, not just the test suite |

The practice this reinforces: **a component that answers a question the rest of the system acts
on needs its own tests, however thin it looks.** `SmtpDirectory` is ninety lines of lookups and
it was the only untested file in the milestone — which is why it held two of the three bugs.

### A6.6 — The administration app cannot read mail, and this is structural

There is no IPC command that returns message content, no gateway method that fetches it, and no
column the read model could select it from — the body is a file outside the database. An
operator diagnosing a delivery needs the envelope: who sent it, from where, to whom, and whether
it landed. Reading customers' mail is not an administrative function, and a screen that offered
it would be used — by an administrator with a grievance, or by whoever compromises one.

A test over the IPC registry asserts that no command's response type is a stream or a byte
array, so adding one is a deliberate act that fails the build.

---

---

## Addendum — decisions taken during Milestone 7

§23 stands. Five decisions, one of which is a bug that had been shipping since Milestone 2.

### A7.1 — A SASL password never becomes a string, and that required changing `IPasswordHasher`

A password that arrives over SASL lives in a `char[]` until it has been hashed and is overwritten
immediately afterwards. A `string` cannot be: it is immutable, it sits on the managed heap until
a collection that may never come, and it can be copied by compaction on the way.

That is only worth doing if nothing downstream re-materialises it, so `IPasswordHasher` gained
`ReadOnlySpan<char>` overloads for `Hash`, `Verify` and `VerifyAgainstDummy` — and the span
versions became the **single implementations**, with the `string` overloads delegating to them
rather than the reverse. Adding an overload that delegated the other way would have looked like
the same work and achieved nothing.

The honest limit: a process dump taken during verification still contains the password. This
shortens the window from "the life of a GC cycle" to "the duration of one Argon2 call". It is a
reduction in exposure, not an elimination of it.

`SaslCredential` has no finaliser, deliberately. A credential cleared at an unpredictable time is
a credential not cleared, and a finaliser would make the `Dispose` contract look optional.

### A7.2 — The mechanism name is never echoed, and the obvious mitigation does not work

`AUTH <base64>` with no mechanism is a malformed exchange but an easy one to produce, and the
credential then arrives in the mechanism-name position. Quoting it back in a `504` puts it in the
client's logs, any intermediary's logs and a packet capture.

The obvious fix — echo the name only when it *looks* like a mechanism name — was written, tested,
and **found not to work**. RFC 4422 §3.1 allows 1–20 characters of `A–Z 0–9 - _`, and a great
many real passwords match that exactly; `hunter2` is a valid mechanism name. There is no test
that separates "a mechanism a client mistyped" from "a password in the wrong field", so the name
is not echoed at all. It goes to the server's own log at debug level, where an operator can see
it and the peer cannot.

Recorded because the first fix was plausible, was written, and would have shipped a credential
leak that a shape test appeared to close.

### A7.3 — Security events on the SMTP path were recorded, logged as recorded, and discarded

The fourth defect of the A4.2 shape, and the worst of them.

Security events are **buffered** rather than written immediately, because writing one inside a
delivery transaction deadlocks SQLite (A2.2). Buffering is only safe if something flushes, and
`FlushAsync` was called from exactly two places: the MediatR pipeline behaviour, and the IPC
dispatcher. **An SMTP session goes through neither.**

So every mailbox authentication failure, every lockout, every forged sender and every rate-limit
refusal was recorded into a buffer, logged at Information level as having been recorded, and
dropped when the connection's scope was disposed. The audit trail for a compromised mailbox —
the one record that answers "when did this start, and from where" — did not exist.

It was found by querying `SecurityEvents` after a live brute-force exercise and seeing an empty
table next to a log full of "Security event MailboxAuthenticationFailed". No test caught it
because every test asserted that the *recorder was called*.

The listener now flushes in a `finally`, so a session that ends the way an attacker's session
ends still leaves its evidence. Four tests fail if the flush is removed.

**The practice this reinforces, again:** for anything that is meant to end up somewhere, assert
that it arrived — not that the code which would send it ran. A4.2 said this about behaviour;
this says it about evidence, which is harder to notice because its absence looks like nothing
happening.

### A7.4 — Authentication entitles a client to its own address and nothing more

`SubmissionPolicy` is the sender-side counterpart of `RelayPolicy`, and exists because
authentication answers a different question from authorisation. Proving who you are does not
entitle you to claim anybody's address.

Without it, one stolen password sends as every colleague — from the real server, over the real
TLS, passing SPF, DKIM and DMARC, because as far as every downstream check is concerned the mail
genuinely is from this domain. That is what a compromised mailbox is worth to an attacker, and
every control downstream of submission is powerless against it.

The null reverse path is refused on submission and accepted on port 25. `<>` is a bounce's
sender; a mail client does not send bounces, and an authenticated client emitting mail that
cannot itself be bounced is a backscatter campaign.

### A7.5 — The rate limit is counted from the database, and what it does not bound is stated

An in-memory window would be faster and would be cleared by a restart — and a limit an attacker
resets by waiting for Patch Tuesday is not a limit. It is counted from the `Messages` table,
which is the true record and survives.

What it does not bound, stated rather than discovered later: a message is counted once
**accepted**, so messages in flight on other connections are not yet visible, and a mailbox can
overshoot by roughly the number of connections it holds open — itself bounded by
`MaxConcurrentConnectionsPerIp`. A counter that reserved capacity before `DATA` would have to
release it on every failure path, and a reservation leaked on one of those paths locks a mailbox
out for an hour.

A rate limit is not a detection mechanism. It is what keeps the blast radius small enough that
detection has time to work.

---

*Document version 1.6 — baseline for Milestone 1, with the Milestone 2–7 addenda.*
