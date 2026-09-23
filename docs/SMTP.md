# SMTP Architecture

> **Status: Milestones 6 and 7 are built and tested; Milestone 8 is not.**
>
> What exists today: the three listener roles, the relay decision, the session state machine
> including the STARTTLS reset, bounded reads, dot-stuffing, streaming receipt to the message
> store, local delivery with alias expansion, and **authenticated submission on 587 and 465**
> with SASL PLAIN and LOGIN, a sender policy and per-mailbox rate limits.
>
> What does not: **outbound delivery** — this server accepts mail but does not yet send it
> onward, which is Milestone 8 — plus **BDAT/CHUNKING** and **SMTPUTF8 as a transport
> extension**. Each is named again below where it appears. See `docs/Standards.md`.

## Three roles, not one listener with a flag

Conflating MTA receipt with client submission is the root cause of most open relays in the
wild. The roles are distinct types with distinct policies.

| Role | Port | TLS | AUTH | Relay | Purpose |
|---|---|---|---|---|---|
| `InboundMta` | 25 | STARTTLS, opportunistic | **Never offered** | **Never** | Mail from the Internet for local domains |
| `Submission` | 587 | STARTTLS **required before AUTH** | Required | For the authenticated mailbox | Mail clients |
| `ImplicitTlsSubmission` | 465 | Implicit from byte zero | Required | For the authenticated mailbox | Mail clients |

All three are enabled by default. The submission listeners refuse every sender until one
authenticates — they fail closed rather than accepting unauthenticated mail (A6.4), and turning
`EnableAuthentication` off does **not** relax that: it makes them refuse everything, which is
the correct behaviour for an operator running this server purely as an inbound MTA.

## The relay decision

The single most important function in the product.

```csharp
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

`Deny` is the fall-through. The function is **total** — there is no default-allow branch
anywhere in it. There is no configuration switch that turns port 25 into an open relay.

**A domain configured here but not Active is not local**, so it reaches `Deny` too. After the
decision, the processor asks the directory whether the domain is configured here at all, and
only the wording and the retry change:

| The recipient's domain | Reply |
|---|---|
| Not configured here | `554 5.7.1 Relay access denied. …` |
| **Pending** — created, not yet enabled | `450 4.3.2 <…>: this domain is not accepting mail yet; try again later` |
| Disabled, or marked for deletion | `554 5.7.1 Relay access denied. …`, as if not hosted |

The Pending case is transient so that mail arriving during a cut-over — the MX published before
the domain was enabled — is retried and delivered rather than bounced, and its log line tells the
operator to enable the domain. None of the three can become an acceptance: the answer is read
only after the policy has refused.

The test suite attempts a relay through every listener role in every authentication state.
Those tests are `OpenRelayTests` in `MailServer.SecurityTests`, and they were Milestone 6's exit
criterion.

They also cover the ways an attacker talks their way into relaying rather than asking for it:
a recipient dressed up as local (the hosted name as a label, a subdomain, the hosted name inside
a quoted local-part), the percent-hack, a source route, `MAIL FROM` claiming a hosted domain,
`EHLO` claiming to be this server, loopback, and RFC 1918 addresses. Two tests assert the
opposite direction on purpose — local delivery is never refused as relaying, and an
authenticated submission session *may* relay — because a suite that only proved refusals would
pass against a server that refused everything.

Structurally: no configuration property may resemble `AllowRelay`, `OpenRelay` or
`TrustLocalNetwork`; the relay allow-list starts empty; and `RelayDecision.Deny` is `0`, so a
decision nobody made refuses.

## The state machine

Explicit transitions, never ad-hoc string matching.

```text
Connected → Greeted → [TlsNegotiated] → [Authenticated] →
MailFromAccepted → RecipientsAccepted → ReceivingData → MessageAccepted
```

### The STARTTLS reset is security-critical

After a successful handshake the session discards the prior EHLO name, **all buffered
pipeline data**, and every piece of envelope state.

Failing to do so is the STARTTLS command-injection class of bug (CVE-2011-0411 and relatives):
an attacker injects plaintext commands before the handshake which are then executed as though
they had arrived inside the TLS tunnel. A dedicated security test asserts that bytes sent
immediately before `STARTTLS` are discarded and never executed.

This is the highest-risk interaction in the whole SMTP implementation, and it is why
`PIPELINING` and `STARTTLS` are called out together in `docs/Standards.md`.

**As built**, three things happen in this order and no other:

1. The `220` is written **and flushed**. It has to be first: the client waits for it before
   starting its handshake, and a `220` sitting in a buffer behind a TLS record the client cannot
   yet read deadlocks the connection.
2. The reader's buffered input is discarded. A **non-empty** discard closes the connection — see
   A6.3: no legitimate client pipelines across STARTTLS, so a peer that does is either broken or
   attacking.
3. The handshake runs, and only on success does `SmtpSessionContext.CompleteTlsHandshake` reset
   the session. A failed handshake leaves the session where it was, because the peer may
   legitimately carry on in the clear.

A **new** `SmtpLineReader` is built over the TLS stream rather than the old one being reused:
reusing it would carry its buffer across the boundary, which is the other half of the same bug.

A reflection test requires every property of `SmtpSessionContext` to be classified as either
cleared by the reset or deliberately surviving it, so adding a field without deciding which it
is fails the build rather than quietly becoming the next STARTTLS injection.

## Capability advertisement

`EHLO` advertises only what is implemented **and currently permitted**:

* `STARTTLS` is not advertised once TLS is active.
* `AUTH` is never advertised on port 25, and not on 587 before TLS.
* `SIZE` reflects the effective limit for this connection.
* Extensions appear only when the feature has passing tests.

**As built**, EHLO advertises `PIPELINING`, `SIZE`, `8BITMIME`, `ENHANCEDSTATUSCODES`,
`STARTTLS` where permitted, and `AUTH PLAIN LOGIN` on a submission listener once TLS is active.
`SMTPUTF8` and `CHUNKING` are behind flags that are off, because neither is implemented.

Advertising an extension that is not honoured is worse than not advertising it, because peers
make delivery decisions from it.

## Submission

### AUTH is offered under three conditions, all required

Authentication is implemented and enabled, the listener is a submission role, and TLS is active.
Dropping any one of them is an incident: without the role check port 25 becomes an
authenticating relay reachable from the Internet; without the TLS check credentials cross the
network in the clear; without the availability check the server advertises a mechanism it cannot
perform.

The conditions are enforced where the capability is advertised **and** again where a mechanism is
selected **and** a third time in `SmtpSessionContext.Authenticate`, which throws if TLS is not
active. A defence that depends on another component being right is not a defence.

**PLAIN and LOGIN only.** Both send the password in a form equivalent to the clear, which is
acceptable only inside TLS — and which is strictly better than a challenge-response mechanism,
because CRAM-MD5 and DIGEST-MD5 require the server to hold something it can compute a response
from. See addendum A5.1.

### The password never becomes a string

A SASL password lives in a `char[]` from the moment it is decoded until it has been hashed, and
is overwritten immediately afterwards. `IPasswordHasher` has `ReadOnlySpan<char>` overloads for
`Hash`, `Verify` and `VerifyAgainstDummy`, and those are the single implementations — the
`string` overloads delegate to them, not the reverse.

This is not a complete defence: a process dump taken during verification still contains the
password. It shortens the window from "the life of a garbage-collection cycle" to "the duration
of one Argon2 call".

`SaslCredential` deliberately has **no finaliser**. A credential cleared at an unpredictable time
is a credential not cleared, and a finaliser would make the `Dispose` contract look optional.

### Authentication refuses uniformly

An unknown address, a disabled mailbox, one not permitted to submit, a wrong password and a
locked-out account all produce `535 5.7.8` and all cost a full Argon2 verification first.

Returning early on an unknown address would make that refusal arrive in microseconds instead of
roughly a hundred milliseconds, and the difference is measurable from anywhere on the Internet.
It would turn the submission port into an address-enumeration oracle, which is the first step of
every credential-stuffing run against a mail server. The security event log is uniform for the
same reason: a description that distinguished the cases would hand the same oracle to whoever
can read the log.

### The submission policy: what a stolen password is worth

An authenticated client may use its own address, or an alias that resolves to it. Nothing else.

Without this, one stolen password sends as every colleague in the organisation — from the real
server, over the real TLS, passing SPF, DKIM and DMARC, because as far as every downstream check
is concerned the mail genuinely is from this domain. That is what a compromised mailbox is worth
to an attacker.

The null reverse path is refused here and accepted on port 25. `<>` is a bounce's sender; a mail
client does not send bounces, and an authenticated client emitting mail that cannot itself be
bounced is the shape of a backscatter campaign.

`SubmissionPolicy` is a total function with `Deny` as the fall-through, like `RelayPolicy`, and
`SubmissionPolicy.MayAuthenticatedSenderUseAnyAddress` is asserted false by a test.

### Two bounds on guessing, doing different jobs

| Bound | Protects | Spends |
|---|---|---|
| `MaxAuthAttemptsPerSession` (3) | Many accounts from one connection | Closes the connection with `421 4.7.0` |
| Mailbox lockout (`MailboxCredential`) | One account across every connection | Locks the account for the lockout duration |

Neither is refunded by anything. In particular the STARTTLS reset does not clear the session's
attempt counter — that counter is this server's own accounting, not knowledge obtained from the
client, so RFC 3207's discard requirement does not reach it, and clearing it would buy an
attacker three more guesses per handshake.

A **cancelled** exchange (`*`) is not a failed attempt. A client that changed its mind has not
guessed a password wrongly, and counting it would walk a hesitant client into a lockout it never
earned. A **malformed** exchange does count, or a client could probe indefinitely with garbage.

`MaxMessagesPerMailboxPerHour` (200) bounds what a successful compromise achieves. It is not a
detection mechanism; it is what keeps the blast radius small enough that detection has time to
work. It is counted from the `Messages` table rather than memory, because a limit cleared by a
restart is a limit an attacker resets by waiting for Patch Tuesday.

## Outbound delivery

A message accepted for onward relay (`RelayDecision.AcceptRelay`) becomes one
`OutboundQueueItem` per recipient, referencing the same stored body every other recipient's row
also references — see `docs/Architecture.md` §8 for why the unit is the recipient, not the
message. `OutboundDeliveryHostedService` claims due items, resolves MX records
(`IDnsResolver`/`DnsMxResolver`, `docs/DNS.md`), orders the results per RFC 5321 §5.1
(`MxSelectionPolicy`), and drives the conversation with `OutboundSmtpClient` — the client-side
mirror of everything above: it issues `EHLO`, negotiates `STARTTLS` opportunistically or refuses
to proceed without it when required (`docs/TLS.md`), sends `MAIL FROM`/`RCPT TO`/`DATA`, and
re-stuffs the stored body on the way out with the same `SmtpDotStuffing` class the receiving side
unstuffed it with on the way in.

A reply's 2xx/4xx/5xx class decides everything downstream: 2xx delivers, 5xx bounces
immediately and generates a DSN (never retried — see A8.2/A8.4 in `docs/Architecture.md` for what
that DSN is and is not), 4xx defers to a time computed by `RetryBackoffPolicy` (1m, 5m, 15m, 30m,
1h, 2h, 4h, 8h, then every 8h until the 5-day expiry window). A message whose own reverse path is
null never generates a DSN on failure, regardless of outcome — the bounce-loop rule.

## Bounded reads everywhere

Every attacker-controlled quantity has a limit, configured in `MailServer:Limits`:

| Limit | Default | Bounds |
|---|---|---|
| `MaxSmtpLineBytes` | 4096 | Command line length |
| `MaxRecipientsPerMessage` | 100 | RCPT flooding |
| `MaxConcurrentConnectionsPerIp` | 10 | Per-source connection exhaustion |
| `MaxConcurrentConnectionsTotal` | 500 | Global exhaustion |
| `SmtpCommandTimeoutSeconds` | 300 | Slowloris |
| `SmtpSessionTimeoutSeconds` | 600 | Infinite sessions |
| `MaxHeaderBytes` | 256 KiB | Header flooding |
| `MaxMimeDepth` | 20 | MIME-bomb nesting |
| `MaxAuthAttemptsPerSession` | 3 | Online password guessing |

`DATA` is streamed to disk in bounded chunks, never buffered whole. `IMessageStore` exposes
`Stream` and has no `byte[] ReadAll()` method to misuse — the API surface enforces the rule, and
a reflection test fails the build if a `byte[]` return ever appears on it.

Two behaviours are worth stating because "bounded" alone does not describe them:

* **An over-long command line latches.** The reader refuses and stays refusing rather than
  skipping to the next CRLF — see A6.2.
* **An over-size message gets a bounded overrun.** RFC 5321 §4.5.3.1.9 wants the server to read
  on to the marker so the sender receives a proper 552 instead of a dropped connection. Reading
  to the marker *without a limit* is the unbounded read this section forbids, so the overrun has
  its own budget (`SmtpDataReceiver.MaxOverrunBytes`, 1 MiB); past it the session is dropped.
  The size is charged against **raw** octets, so padding with stuffed dots cannot buy a sender
  extra room, and the trace header this server prepends is not charged to the peer at all.

## Hard parts

These get extra test investment because "almost right" is indistinguishable from broken.

1. **Dot-stuffing.** ✅ **Built.** A leading `.` is unstuffed on receipt and stuffed on send. A
   body legitimately containing `\r\n.\r\n` does not truncate — the round-trip tests include a
   message whose body is itself an SMTP transcript with a marker in it. Bare `\n` is normalised
   *after* the terminator has been decided on raw octets, which is the ordering that prevents
   SMTP smuggling; see A6.1 in `docs/Architecture.md`.
2. **PIPELINING + STARTTLS.** ✅ **Built.** See above. Mutation-verified: removing the refusal
   fails the injection test.
3. **BDAT / CHUNKING.** ⛔ **Not built.** Not advertised, so no peer will attempt it.
4. **SMTPUTF8 and IDNA.** ⚠️ **Partial.** The address model round-trips Unicode and punycode
   without loss and the path parser preserves it, but the transport extension is not advertised,
   so nothing downgrades yet.
5. **Graceful shutdown mid-`DATA`.** ✅ **Built.** `SmtpDataReceiver` is passed the host
   shutdown token rather than the session token, so an in-flight message finishes even as the
   host stops; the listener then waits `MailServer:Smtp:ShutdownGraceSeconds` for sessions to
   end. Abandoning a delivery mid-`DATA` risks a duplicate at the sending server, which saw no
   reply and will retry.
6. **MX selection, fallback and failure classification.** ✅ **Built.** `IDnsResolver` collapses
   every DNS outcome to Success/Temporary/Permanent before the queue worker ever sees it,
   handles the implicit-MX fallback to a domain's own A/AAAA record internally, and treats a
   published null MX (RFC 7505) as an immediate permanent failure. Getting the
   temporary/permanent split wrong either bounces mail that would have gone through on retry or
   retries a domain that will never answer.
7. **Bounce-loop prevention.** ⚠️ **Partial.** A message with a null reverse path never generates
   a DSN on failure. Detecting an inbound `Auto-Submitted` header to suppress a DSN the same way
   is not built — that needs header parsing, which arrives with MIME in Milestone 9. See
   A8.4 in `docs/Architecture.md`.

## What was verified against a running server

Milestone 6 was not signed off on the test suite alone. Against the real service on a real
socket: the schema migrated to version 6, the listener bound, a message was accepted and
delivered to `INBOX` at UID 1, a second arrived through an alias at UID 2 with the recipient row
naming **the address the sender wrote** rather than the mailbox behind it, mailbox quota was
charged, a relay attempt was refused `554 5.7.1`, and `EHLO` advertised no `AUTH`.

Two of the three bugs recorded in A6.5 were found by that exercise and not by the tests.

**Milestone 7** was verified the same way, with Python's `smtplib` rather than a hand-written
client — an independent implementation doing its own EHLO parsing, STARTTLS and AUTH
negotiation. Over both 587 and 465: no `AUTH` advertised before TLS, `AUTH PLAIN LOGIN` after it,
login and send succeeding, `AUTH LOGIN` driven by hand through its two challenges, a wrong
password and an unknown mailbox answered identically, three wrong passwords closing the
connection with 421, `AUTH` before TLS refused 530, `AUTH` on port 25 refused 502 and never
advertised, alice refused when sending as bob but accepted when sending as an alias she is
behind, the null reverse path refused on 587 and accepted on 25, and both submissions delivered
to the recipient's INBOX.

That exercise found the third bug of the A6.5 shape — see A7.3.

**Milestone 8** was verified the same way in spirit, with one honest difference: there is no
independent client library that plays a *remote MX*, so `FakeRemoteMta` — a real `TcpListener`
answering with a real self-signed certificate over a real TLS handshake — stands in for one, and
the production `OutboundSmtpClient` is driven against it exactly as `smtplib` drove the real
listener above. Over a real loopback socket: a message was accepted and the fake's own reply
code, reverse path and body all matched what was sent (including a body line that is itself a
bare `.`, round-tripping through dot-stuffing intact); a `550` at `RCPT TO` was classified
permanent and a `452` at `DATA` was classified temporary; TLS was negotiated and used against an
untrusted certificate when opportunistic, and refused to fall back to plaintext — whether the
certificate was untrusted or `STARTTLS` was never offered — when required; and a closed port
failed as a temporary result rather than an unhandled exception. This server has not yet
exchanged mail with a live Internet mail exchanger — see `docs/Standards.md`'s known gaps.
