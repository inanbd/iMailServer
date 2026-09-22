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
| Malicious content | Layered pipeline; quarantine; `IMalwareScanner` delegating to a real engine | **12** |
| Becoming a spam source | Per-mailbox limits; per-address inbound rate limits; no evasion features | **12** |
| Supply chain | Central package management, pinned versions, nuget.org only | **1** |

Items marked **1** are implemented and tested now. Items marked **12** are implemented and
tested as of Milestone 12, with the caveat `docs/Filtering.md` records: the filter has never
been run against live mail, and `IMalwareScanner` ships no engine — only the seam for one.
Outbound anomaly detection is **not** built; what bounds this server as a spam source is the
per-mailbox submission rate limit from Milestone 7.

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

## Administrator authentication

Milestone 2 replaces "whoever can open the pipe is an administrator" with an explicit
credential. This is the change that makes the rest of the product defensible: before it, any
process running as a local administrator could drive the service.

### First-run setup

The server ships with no account and no default password. `Security.SetupStatus` reports
`RequiresSetup`, the administration application shows the setup wizard, and
`Security.CompleteSetup` creates the single built-in administrator.

`CompleteSetup` refuses outright once an account exists. Without that refusal it would be a
remote "seize this server" endpoint, since it is reachable without a session.

Setup returns a **recovery key** exactly once. It is shown, it is not stored in plaintext, and
it cannot be re-displayed. See [Recovery](#recovery) below.

### Password storage

Argon2id (RFC 9106), via `Konscious.Security.Cryptography.Argon2`. The BCL has no Argon2, and
PBKDF2 is materially weaker against GPU attack.

Defaults are 64 MiB of memory, 3 passes, 2 lanes. They are configurable upward, and the stored
verifier is self-describing:

```
$argon2id$v=19$m=65536,t=3,p=2$<salt>$<digest>
```

Because the work factors travel with the hash, raising them does not invalidate existing
passwords. `Verify` reports `NeedsRehash`, and the handler re-hashes at the one moment the
plaintext is legitimately available — immediately after a successful sign-in.

Passwords are never encrypted for reversible storage. Anything passed to `ISecretProtector` is
something the server must read back; a password is not.

`PasswordHash.ToString()` deliberately omits the digest, so an accidentally logged or
serialised value yields `argon2id (m=65536,t=3,p=2)` and nothing else.

### Password policy

Minimum 12 characters, maximum 256, and a short list of forbidden values. There are
deliberately **no composition rules** — no "one uppercase, one digit, one symbol". NIST
SP 800-63B withdrew that guidance because it reliably produces `Password1!` while blocking
genuinely strong passphrases. Length and a blocklist are what remain effective.

The maximum exists because Argon2 cost is not bounded by input length and a megabyte-long
password is a cheap way to make the server work hard.

### Failure handling

Every authentication failure returns the same message — "The master password is not correct." —
whether the account does not exist, the password is wrong, or the stored verifier is corrupt.
Distinguishable messages are an enumeration oracle.

Timing is equalised as well as wording:

- No account: `VerifyAgainstDummy` spends the full Argon2 cost against a built-in verifier, so
  "not set up" and "wrong password" cannot be told apart by how long the call took.
- An **empty** candidate also spends the full cost. Konscious throws on empty password bytes,
  and an exception has both a different shape and a different duration from an ordinary
  failure — which would reopen the oracle the rest of this design closes.

A test asserts the ratio between the two timings stays inside a 0.2–5.0 band. It is a coarse
bound on purpose: a tight one would flake on a shared build agent, and a coarse one still
catches the failure that matters, which is a whole Argon2 computation being skipped.

### Lockout

Consecutive failures are counted in the database, not in memory, because lockout that resets on
service restart is no lockout at all. After five failures the account locks for 15 minutes, and
the duration doubles at each further multiple of the threshold up to a cap of 8 hours. The
counter resets after an hour without a failure, so an administrator who mistypes twice a month
never accumulates a lockout.

Lockout is checked **before** the password is verified, so a locked-out attacker cannot keep
the server doing Argon2 work. That makes a locked-out attempt observably faster, which is
acceptable: lockout state is not a secret, and `Security.SetupStatus` reports it so the sign-in
screen can show a countdown rather than a bare rejection.

> **`AuthenticateCommand` is deliberately not transactional, and this is a security property.**
> A failed attempt increments the persisted counter and then throws, and `TransactionBehavior`
> rolls back on exception — so a transaction here would discard the very increment that drives
> lockout. Brute-force protection would be silently inert while appearing entirely correct in
> configuration and in the logs. This was a real defect in development, caught by the tests in
> `MailServer.SecurityTests`, and there is now a structural test asserting the marker interface
> is absent.

### Recovery

The recovery key is 25 characters of Crockford base32 — `I`, `L`, `O` and `U` are excluded, so
it can be read aloud and transcribed without ambiguity — giving 125 bits of entropy. It is
stored Argon2id-hashed, exactly like a password.

`Security.ResetPasswordWithRecoveryKey` is reachable without a session, which it must be, and
is safe for that reason: 125 bits is not guessable. It deliberately **bypasses lockout**,
because an attacker who can trigger lockout should not thereby be able to lock the legitimate
administrator out of their own recovery path.

The key is single-use. A successful reset consumes it, issues a replacement, and sets
`MustChangePassword` so the next sign-in must choose a new password before anything else is
reachable.

There is no other recovery path. No support backdoor, no "reset by deleting a file". If the key
and the password are both lost, the database must be recreated — which is the correct trade,
because any recovery mechanism weaker than the credential it recovers becomes the real
credential.

---

## Sessions

A successful sign-in issues a 256-bit random token. The client holds it in memory; the server
stores only its SHA-256 hash, so a memory dump of the service or a stray log line does not yield
a usable token.

**Sessions live in memory only and do not survive a service restart.** That is the intended
behaviour: a restart is the one moment when "sign in again" is both cheap and unambiguous, and
persisted sessions would be one more thing a database copy could steal. Lockout state, by
contrast, *is* persisted — the asymmetry is deliberate. Restarting must never clear a lockout,
and it must never preserve a session.

Two independent timeouts apply. An idle timeout (default 20 minutes) slides on each validated
request; an absolute timeout (default 12 hours) does not. The idle timer is what the WPF
`IdleMonitor` mirrors locally so the UI locks itself before the server would refuse it.

At most 128 concurrent sessions are held, with least-recently-used eviction. The bound exists so
a client in a reconnect loop cannot grow the table without limit.

Every session-bearing operation runs under the identity the *session* carries. The Windows
identity of the calling process no longer confers any permission — `ResolveCaller` returns
`AdminPermission.None` — so the pipe ACL is now defence in depth rather than the authorisation
mechanism.

### IPC protocol version 2

Version 2 adds a per-request `SessionToken` and refuses version 1 outright, because a v1 client
is by definition one that expects to administer the server without signing in.

Exactly four commands are reachable without a session, and the registry enforces agreement
between the descriptor's `RequiresSession` flag and the request type's `IAnonymousRequest`
marker **in both directions** — a mismatch throws at construction, in the service's first second
of life:

| Command | Why it is safe without a session |
|---|---|
| `Security.SetupStatus` | Reveals only whether setup is needed and whether sign-in is locked out — both required to draw the right screen |
| `Security.CompleteSetup` | Refuses once an account exists |
| `Security.Authenticate` | Is the sign-in itself |
| `Security.ResetPasswordWithRecoveryKey` | Gated by 125 bits of entropy |

Every other command is refused with `Unauthenticated` before its payload is deserialised. The
refusal is identical whether the token is missing, forged, expired or revoked; the real reason
goes to the service log, where an attacker cannot read it. `MailServer.Ipc.Tests` drives this
from the registry itself, so a command added in a later milestone is covered the moment it is
registered.

When `MustChangePassword` is set, `AuthorizationBehavior` refuses every request except the ones
marked `IAllowedWhenPasswordChangeRequired`. A session that must change its password can change
it and sign out, and nothing else.

---

## Audit and security events

Two logs, deliberately separate, because they answer different questions and need opposite
consistency guarantees.

**The audit trail** records what an administrator changed. It joins the request's transaction,
so an audit record and the change it describes commit or roll back together. There is no state
in which the audit trail describes a change that did not happen.

**The security event log** records authentication and session activity. It must survive the
rollback of the thing it describes — a failed sign-in is precisely the case where the operation
is rejected but the record must persist. Events are therefore buffered during the request and
flushed from `UnhandledExceptionBehavior`'s `finally`, which runs after commit or rollback.

That buffering is not stylistic. Writing security events on a second connection while the
request's write transaction was open deadlocked against SQLite's single-writer lock: each event
stalled for the full busy timeout and was then silently dropped. The suite went from seconds to
five and a half minutes and four tests failed, which is how it was found.

Neither log ever contains a secret value. `IAuditTrail` records the *fact* of a password change,
never the password; `SecurityEvent` descriptions are written by the handler, never interpolated
from request payloads.

---

## Reporting a vulnerability

Do not open a public issue. Contact the maintainers privately with reproduction steps and a
window for a fix before disclosure.
