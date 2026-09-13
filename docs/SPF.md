# SPF

> **Status: Planned — Milestone 9.**

Sender Policy Framework (RFC 7208) lets a domain owner declare which IPs may send mail using
that domain in the SMTP `MAIL FROM`.

## A starting record

```text
example.com.   TXT   "v=spf1 mx ip4:203.0.113.10 -all"
```

| Mechanism | Meaning |
|---|---|
| `mx` | The domain's MX hosts may send |
| `a` | The domain's A/AAAA hosts may send |
| `ip4:` / `ip6:` | A specific address or CIDR range |
| `include:` | Defer to another domain's record (for a mail provider) |
| `redirect=` | Replace this record entirely with another domain's |
| `~all` | Softfail — "not authorised, but do not reject" |
| `-all` | Fail — "not authorised, reject" |

## `~all` or `-all`

Start with `~all` while you verify that everything legitimately sending as your domain is
covered — the marketing platform, the ticketing system, the backup notifier. Move to `-all`
once DMARC aggregate reports show no legitimate sources failing.

`-all` published too early causes legitimate mail to be rejected, and the reports that would
have told you which sources were missing arrive after the damage.

## The lookup limits

SPF evaluation **must not exceed 10 DNS-querying mechanisms**, and no more than 2 of those may
be void lookups. Exceeding either is a `permerror`, which most receivers treat as a failure.

`include:` is the usual culprit: each one costs a lookup, and each nested record inside it
costs more. Three mail providers can silently blow the budget.

The implementation enforces both limits and reports `permerror` rather than continuing to
evaluate, because partial evaluation would produce a result the rest of the world disagrees
with. The diagnostics screen shows the running lookup count against a record so the problem is
visible before it is published.

## Evaluation (inbound)

SPF is evaluated against the SMTP `MAIL FROM` domain, with a `HELO` fallback when the reverse
path is null (as it is for DSNs).

Its result feeds DMARC: SPF passes for DMARC only if the `MAIL FROM` domain **aligns** with the
`From` header domain.

## Why SPF alone is not enough

SPF authorises the envelope sender, not the `From:` header the user sees. An attacker can pass
SPF for their own domain while displaying your domain in `From:`. Only DMARC ties the two
together, which is why the three are deployed as a set.

## Forwarding breaks SPF

When a message is forwarded, the forwarding server becomes the sender — and it is not in your
SPF record. This is expected and unavoidable.

The mitigations are DKIM (which survives forwarding, since the signature travels with the
message) and SRS (which rewrites the envelope sender so the forwarding hop passes SPF without
touching the `From:` header). See `docs/DMARC.md`.
