# SMTP Architecture

> **Status: Milestone 6 is built and tested; Milestones 7 and 8 are not.**
>
> What exists today: the three listener roles, the relay decision, the session state machine
> including the STARTTLS reset, bounded reads, dot-stuffing, streaming receipt to the message
> store, and local delivery with alias expansion. 472 tests in `MailServer.Smtp.Tests` plus the
> open-relay suite in `MailServer.SecurityTests`.
>
> What does not: **AUTH** (Milestone 7 — the submission listeners therefore ship disabled),
> **BDAT/CHUNKING**, **SMTPUTF8 as a transport extension**, and **outbound delivery**
> (Milestone 8). Each is named again below where it appears. See `docs/Standards.md`.

## Three roles, not one listener with a flag

Conflating MTA receipt with client submission is the root cause of most open relays in the
wild. The roles are distinct types with distinct policies.

| Role | Port | TLS | AUTH | Relay | Purpose |
|---|---|---|---|---|---|
| `InboundMta` | 25 | STARTTLS, opportunistic | **Never offered** | **Never** | Mail from the Internet for local domains |
| `Submission` | 587 | STARTTLS **required before AUTH** | Required | For the authenticated mailbox | Mail clients |
| `ImplicitTlsSubmission` | 465 | Implicit from byte zero | Required | For the authenticated mailbox | Mail clients |

Only `InboundMta` is enabled by default. The two submission listeners require AUTH, AUTH
requires SASL, and SASL lands in Milestone 7 — so today they would refuse every sender. That
refusal is correct (see A6.4 in `docs/Architecture.md`: they fail closed rather than accepting
unauthenticated mail), but a port advertised and unusable is worse than one absent, so they are
off until the mechanism exists.

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

**As built**, EHLO advertises `PIPELINING`, `SIZE`, `8BITMIME`, `ENHANCEDSTATUSCODES`, and
`STARTTLS` where permitted. `SMTPUTF8` and `CHUNKING` are behind flags that are off, because
neither is implemented; `AUTH` is behind the same kind of flag for Milestone 7.

Advertising an extension that is not honoured is worse than not advertising it, because peers
make delivery decisions from it.

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

## What was verified against a running server

Milestone 6 was not signed off on the test suite alone. Against the real service on a real
socket: the schema migrated to version 6, the listener bound, a message was accepted and
delivered to `INBOX` at UID 1, a second arrived through an alias at UID 2 with the recipient row
naming **the address the sender wrote** rather than the mailbox behind it, mailbox quota was
charged, a relay attempt was refused `554 5.7.1`, and `EHLO` advertised no `AUTH`.

Two of the three bugs recorded in A6.5 were found by that exercise and not by the tests.
