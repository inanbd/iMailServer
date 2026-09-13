# SMTP Architecture

> **Status: Planned — Milestones 6, 7 and 8.** This documents the design the implementation
> will follow, not behaviour that exists today. See `docs/Standards.md`.

## Three roles, not one listener with a flag

Conflating MTA receipt with client submission is the root cause of most open relays in the
wild. The roles are distinct types with distinct policies.

| Role | Port | TLS | AUTH | Relay | Purpose |
|---|---|---|---|---|---|
| `InboundMta` | 25 | STARTTLS, opportunistic | **Never offered** | **Never** | Mail from the Internet for local domains |
| `Submission` | 587 | STARTTLS **required before AUTH** | Required | For the authenticated mailbox | Mail clients |
| `ImplicitTlsSubmission` | 465 | Implicit from byte zero | Required | For the authenticated mailbox | Mail clients |

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

The test suite attempts a relay through every listener role in every authentication state, and
those tests are an exit criterion for Milestone 6.

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

## Capability advertisement

`EHLO` advertises only what is implemented **and currently permitted**:

* `STARTTLS` is not advertised once TLS is active.
* `AUTH` is never advertised on port 25, and not on 587 before TLS.
* `SIZE` reflects the effective limit for this connection.
* Extensions appear only when the feature has passing tests.

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
`Stream` and has no `byte[] ReadAll()` method to misuse — the API surface enforces the rule.

## Hard parts

These get extra test investment because "almost right" is indistinguishable from broken.

1. **Dot-stuffing.** A leading `.` must be unstuffed on receipt and stuffed on send. A body
   legitimately containing `\r\n.\r\n` must not truncate. Bare `\n` from sloppy clients must be
   normalised without corrupting content.
2. **PIPELINING + STARTTLS.** See above.
3. **BDAT / CHUNKING.** Exact byte counting, `LAST` semantics, error recovery mid-chunk.
4. **SMTPUTF8 and IDNA.** Punycode for transport, UTF-8 for display, correct downgrade when
   the remote lacks the extension. Never silently mangle an address — the address model
   already round-trips both directions and is tested.
5. **Graceful shutdown mid-`DATA`.** Abandoning a delivery mid-`DATA` risks a duplicate at the
   remote server, so shutdown lets in-flight `DATA` complete.
