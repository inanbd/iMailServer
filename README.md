# AetherMail Server

A production-grade, self-hosted email server for Windows Server, written in C# on .NET 10.

This is a complete mail platform — SMTP receipt, authenticated submission, direct Internet
delivery, IMAP access, DKIM/SPF/DMARC, automatic TLS certificates and deliverability
diagnostics — not an SMTP sending utility.

> **Status: Milestone 8 of 13 complete.** The foundation, security, certificates, ACME, mailbox
> administration, SMTP inbound and submission, and now outbound delivery — MX resolution, the
> queue, retry, per-domain throttling and bounce/delay DSNs — are built, compile with warnings as
> errors, and are covered by 2,084 passing tests. This server can receive mail from the Internet,
> accept authenticated submission from a mail client, and relay it onward to another server's MX;
> it does not yet do so with DKIM/SPF/DMARC signing or offer IMAP access. See
> [Roadmap](#roadmap) for what lands when, and `docs/Standards.md` for exactly which standards
> are implemented versus planned. Nothing is described as working until it has tests.

---

## What exists today

| Component | State |
|---|---|
| Clean Architecture solution, 13 projects | Built, dependency rule enforced by tests |
| CQRS with MediatR and 8 pipeline behaviors | Built, order locked in by tests |
| Domain model (`MailDomain` aggregate, value objects, policies) | Built and tested |
| SQLite provider (WAL, busy timeout, write serialisation) | Built and tested against a real database |
| SQL Server provider (dialect, retry classification, `sp_getapplock`) | Built; needs a SQL Server instance to exercise |
| Migration runner (checksums, advisory lock, fail-safe) | Built and tested |
| Secure named-pipe IPC (framed, ACL'd, allow-listed commands) | Built and tested end to end |
| Windows Service host with startup gates and resilient workers | Built; starts, migrates, serves IPC |
| WPF administration application | Built; setup wizard, lock screen, dashboard and domain management over IPC |
| Administrator authentication (Argon2id, lockout, recovery key) | Built and tested end to end |
| Session-based IPC authorization (protocol v2) | Built; enforcement driven from the command registry by tests |
| DPAPI-backed secret store | Built and tested; DPAPI path needs Windows CI |
| Audit trail and security event log | Built and tested |
| TLS certificates (self-signed, PFX import, Windows store) | Built and tested |
| Hot certificate reload without restarting listeners | Built; proven by test, no restart required |
| Certificate expiry monitoring and health | Built and tested |
| ACME / Let's Encrypt issuance and renewal | Built; tested against a fake CA, **not yet against Let's Encrypt** — see [LetsEncrypt.md](docs/LetsEncrypt.md) |
| Rate-limit and pre-flight protection | Built and tested |
| Mailboxes, credentials, quotas and folders | Built and tested |
| Aliases with cycle and fan-out protection | Built and tested |
| SMTP inbound (listener, relay protection, local delivery) | Built and tested against a real MTA-shaped client |
| SMTP submission (587/465, SASL PLAIN/LOGIN, per-mailbox rate limits) | Built and tested; a real client (Python's `smtplib`) authenticates and submits |
| Outbound MTA (MX resolution, delivery client, queue, retry, per-domain throttling, DSNs) | Built and tested against a fake remote MX over a real socket; **not yet exercised against a live Internet mail exchanger** — see `docs/Standards.md` |
| IMAP, POP3, DKIM/SPF/DMARC, filtering | **Not yet built** — milestones 9–12 |

---

## Architecture at a glance

```text
┌──────────────────────────────────────────────────────────────┐
│  MailServer.Service  —  THE MAIL SERVER (Windows Service)    │
│  Listeners · queues · certificates · timers · IPC server     │
└──────────────────────────────┬───────────────────────────────┘
                               │ ACL-restricted named pipe
┌──────────────────────────────┴───────────────────────────────┐
│  MailServer.Admin  —  A MANAGEMENT CONSOLE (WPF)             │
│  Closing it does not stop mail. It cannot reach the database.│
└──────────────────────────────────────────────────────────────┘
```

Dependencies point inward only: `Hosts → Infrastructure → Application → Domain`.
`MailServer.Domain` references nothing but the BCL, and a test fails the build if that ever
changes.

The full 30-section architecture decision record is in
**[`docs/Architecture.md`](docs/Architecture.md)**.

### Two decisions worth knowing up front

**The administration application physically cannot touch the database.** It does not
reference either persistence project, so `Microsoft.Data.Sqlite` and
`Microsoft.Data.SqlClient` are absent from its dependency closure. "No UI directly editing
the database" is a compile-time guarantee here, not a code-review convention.

**The IPC layer resolves commands through a hand-written allow-list**, never
`Type.GetType` on a wire string. Accepting an assembly-qualified type name over a pipe would
hand anyone who can reach it the ability to instantiate arbitrary types inside the service —
a remote code execution primitive traded away for the convenience of not writing a dictionary.

---

## Requirements

### Build

* .NET 10 SDK
* Windows, or any platform for the cross-platform projects
  (the WPF app compiles anywhere with `EnableWindowsTargeting`, which
  `Directory.Build.props` sets automatically off Windows)

### Run in production

* Windows Server 2019 / 2022 / 2025, x64
* A **static public IP** with **PTR (reverse DNS) control**
* **Inbound and outbound TCP 25** — see the warning below
* SQLite (small installations) or Microsoft SQL Server (recommended for production)

> **Port 25 is blocked by default on most cloud providers and nearly all residential ISPs.**
> Azure blocks outbound 25 on almost every subscription with no exception process; AWS and GCP
> require a request. Without outbound 25 the server cannot deliver mail directly at all, and
> you must configure a smarthost relay. The pre-flight check detects this and says so
> plainly. See `docs/Troubleshooting.md`.

---

## Getting started

```bash
git clone https://github.com/inanbd/iMailServer.git
cd iMailServer

dotnet build MailServer.sln
dotnet test  MailServer.sln
```

### Run the service for development

On Linux or macOS the service runs as a console application — `UseWindowsService()` is a
no-op unless the Service Control Manager actually launched the process.

```bash
cd src/MailServer.Service

DOTNET_ENVIRONMENT=Development dotnet run -- \
  --MailServer:Storage:DataRoot=./Data \
  --MailServer:Database:Sqlite:DataSource=./Data/mailserver.db
```

Expected output on a first run:

```text
[INF] Database provider: SQLite.
[INF] AetherMail Server starting.
[INF] Created data directory ./Data/Messages.
…
[INF] IPC server starting on pipe 'AetherMail.Admin' with 8 concurrent instance(s).
[INF] Applying 1 migration(s): 0001_InitialSchema.
[INF] Applied migration 0001 'InitialSchema' in 4 ms.
[INF] Database schema migrated from version 0 to 1.
[INF] Application started. Press Ctrl+C to shut down.
```

Run it again and the migration is skipped — "never twice" is the runner's first guarantee,
and it is covered by a test.

`appsettings.Development.json` selects the file-backed development secret protector, because
DPAPI is Windows-only. That protector refuses to initialise when the environment is
`Production` and logs a Critical warning on every start; there is no silent fallback.

### Run the administration application

```bash
cd src/MailServer.Admin
dotnet run          # Windows only at runtime
```

It requires elevation: the pipe's ACL admits only the local Administrators group and the
service account, so an unelevated process cannot connect at all.

#### First run

The server ships with **no account and no default password**. On first connection the
application shows a setup wizard that creates the single built-in administrator, then displays
a recovery key **once**.

Write the recovery key down before continuing. It cannot be shown again, it is stored only as
an Argon2id hash, and there is no other way back in — no support backdoor and no "delete a file
to reset". That is deliberate: any recovery path weaker than the credential it recovers becomes
the real credential. If both the password and the key are lost, the database must be recreated.

After setup, every subsequent launch asks for the master password. Being a local administrator
is no longer sufficient to administer the server; see [Security.md](docs/Security.md).

---

## Repository layout

```text
MailServer.sln
Directory.Build.props        # nullable, warnings-as-errors, analyzers
Directory.Packages.props     # central package management, one version each
NuGet.config                 # nuget.org only

src/
  MailServer.Domain/                 # entities, value objects, policies — BCL only
  MailServer.Application/            # use cases, ports, pipeline behaviors
  MailServer.Infrastructure/         # provider-neutral adapters
  MailServer.Persistence.Sqlite/     # dialect + connection factory + migrations
  MailServer.Persistence.SqlServer/  # dialect + connection factory + migrations
  MailServer.Ipc/                    # wire contract, framing, client and server
  MailServer.Service/                # Windows Service host — the real server
  MailServer.Admin/                  # WPF administration application

tests/
  MailServer.Domain.Tests/           # 268 tests
  MailServer.Application.Tests/      #  51 tests
  MailServer.Infrastructure.Tests/   #  71 tests
  MailServer.Ipc.Tests/              # 138 tests (end to end over a real pipe, incl. session enforcement)
  MailServer.Persistence.Tests/      #  56 tests (against real SQLite)
  MailServer.SecurityTests/          # 779 tests (real Argon2, real SQLite, no-bypass source scan)
  MailServer.Certificates.Tests/     #  51 tests (real certificate generation and hot reload)
  MailServer.Acme.Tests/             #  37 tests (issuance against a fake CA, DNS parsing, limits)
  MailServer.Mailboxes.Tests/        #  42 tests (quota enforcement, aliases, full CRUD)
  MailServer.Smtp.Tests/             # 573 tests (wire-level: grammar, dot-stuffing, STARTTLS, open-relay matrix)
  MailServer.Outbound.Tests/         #  18 tests (delivery client and queue worker against a fake remote MX)
```

Projects for milestones 4–13 are created **in** those milestones. A solution full of empty
assemblies looks finished and provides no compile-time value.

---

## Documentation

| Document | Contents |
|---|---|
| [Architecture.md](docs/Architecture.md) | The 30-section decision record — read this first |
| [CleanArchitecture.md](docs/CleanArchitecture.md) | Layer rules and how they are mechanically enforced |
| [CQRS.md](docs/CQRS.md) | Commands, queries, and why the pipeline is ordered as it is |
| [Persistence.md](docs/Persistence.md) | Repositories, transactions, migrations |
| [Sqlite.md](docs/Sqlite.md) | WAL, write serialisation, when to move to SQL Server |
| [SqlServer.md](docs/SqlServer.md) | Isolation, queue patterns, backups |
| [Security.md](docs/Security.md) | Threat model, authentication, sessions, audit |
| [Certificates.md](docs/Certificates.md) | Sources, bindings, hot reload, the never-downgrade rule |
| [LetsEncrypt.md](docs/LetsEncrypt.md) | ACME, challenges, rate limits, and what is not yet proven |
| [Standards.md](docs/Standards.md) | Every standard, with an honest Implemented/Partial/Planned status |
| [Installation.md](docs/Installation.md) | Installing and configuring |
| [Troubleshooting.md](docs/Troubleshooting.md) | Port 25, DNS, certificates, reputation |
| [SMTP.md](docs/SMTP.md) · [IMAP.md](docs/IMAP.md) · [DNS.md](docs/DNS.md) | Protocol design |
| [DKIM.md](docs/DKIM.md) · [SPF.md](docs/SPF.md) · [DMARC.md](docs/DMARC.md) | Mail authentication |
| [TLS.md](docs/TLS.md) · [Certificates.md](docs/Certificates.md) · [LetsEncrypt.md](docs/LetsEncrypt.md) | Transport security |
| [Deliverability.md](docs/Deliverability.md) | The scoring model and what it does not promise |
| [BackupRestore.md](docs/BackupRestore.md) | Backups, and the DPAPI machine-scope trap |
| [WindowsServer.md](docs/WindowsServer.md) | Service account, firewall, hardening |

---

## Roadmap

| # | Milestone | Status |
|---|---|---|
| 1 | Core Foundation | **Complete** |
| 2 | Security & Administration (Argon2id, DPAPI store, audit) | **Complete** |
| 3 | Certificate Infrastructure | **Complete** |
| 4 | ACME / Let's Encrypt | **Complete** |
| 5 | Domain Administration (mailboxes, aliases, quotas) | **Complete** |
| 6 | SMTP Inbound + relay protection | **Complete** |
| 7 | SMTP Submission | **Complete** |
| 8 | Outbound MTA | **Complete** |
| 9 | Mail Authentication (DKIM/SPF/DMARC) | Next |
| 10 | IMAP (+ optional POP3) | Planned |
| 11 | Deliverability | Planned |
| 12 | Filtering | Planned |
| 13 | Production Hardening (installer, backups, migration) | Planned |

Exit criteria for each are in `docs/Architecture.md` §27.

---

## A note on expectations

Running a public mail server well is mostly an operations problem, not a software problem.
Perfect SPF, DKIM and DMARC will not make a brand-new IP address trusted by Gmail or
Microsoft 365 — reputation is earned over weeks of well-behaved sending, and no software can
shortcut it.

This product reports **readiness**, never guaranteed inbox placement, and the documentation
says so wherever the question arises. It also contains no features for evading reputation
systems: no IP rotation, no retry-storm behaviour, no attempt to circumvent provider
throttling. When a destination asks us to slow down, we slow down.

## Licence

Not yet determined. Note that MediatR is pinned to 12.5.0 — the last Apache-2.0 release —
and that decision is documented as risk 1 in `docs/Architecture.md` §28.
