# Deliverability

> **Status: Planned — Milestone 11.**

## What this product promises, and what it does not

**It reports readiness.** Every technical prerequisite for mail to be accepted — correct DNS,
verified authentication, trusted TLS, a clean relay posture, a healthy queue — is checked,
scored, and explained with evidence.

**It does not promise inbox placement, and never will.** Reputation is earned over weeks of
well-behaved sending from a stable IP. A brand-new address is untrusted by Gmail and Microsoft
365 regardless of a perfect 100/100 score, and no software can shortcut that.

Any product claiming otherwise is either misinformed or selling something. Wherever this
question arises in the UI, the answer given is the one above.

## The score

| Category | Weight | Checks |
|---|---|---|
| Identity | 20 | A/AAAA, PTR, FCrDNS, EHLO name matching PTR |
| Authentication | 30 | SPF present and sane, DKIM published and matching, DMARC present, alignment verified by a real self-test message |
| TLS | 20 | Certificate trusted, hostname matches, expiry, renewal health, STARTTLS offered, MTA-STS, TLS-RPT |
| DNS | 15 | MX correct, no lookup-limit breach, TTL sanity, CAA sanity |
| Reputation | 10 | `IReputationProvider` results, cached and rate-limited |
| Operations | 5 | Open-relay test, queue health, disk, clock skew, bounce rate |

Every check returns `Pass` / `Warn` / `Fail` / `Inconclusive` **with evidence**: the record
actually found, the value expected, the resolver used, the TTL observed.

The UI shows exactly how the total was computed. A bare "94/100" that cannot be explained is
useless to an operator trying to fix the missing six.

## Authentication is weighted highest for a reason

SPF, DKIM and DMARC are the checks a receiver can evaluate on the very first message from an
unknown sender. Everything else — volume patterns, complaint rates, engagement — takes time to
accumulate. Getting authentication right is the part that is entirely within your control and
entirely verifiable before you send anything.

## Delivery test

Sends a real message to an address you nominate and records the whole conversation:

```text
MX selected · remote address · SMTP banner · EHLO capabilities
STARTTLS · TLS version · certificate details
MAIL FROM result · RCPT result · DATA result · remote final response
queue latency · delivery latency · DKIM selector used · Message-ID
```

Sending to a Gmail account and reading the `Authentication-Results` header it adds is the
fastest honest answer to "is my setup correct?" — it is the receiver's own verdict rather than
our opinion of it.

## Header analyser

Paste raw headers; get SPF, DKIM, DMARC and ARC results with the reasoning, plus the
`Received` chain, `Return-Path`, `Reply-To` and `List-Unsubscribe`.

Useful in both directions: diagnosing why your mail was refused, and diagnosing why something
arrived that should not have.

## Reputation providers

`IReputationProvider` is an abstraction with caching and rate limiting.

Naïve DNSBL querying from a busy MTA gets you blocked by the DNSBL operator and is an abuse of
volunteer infrastructure. Results are cached and queries are rate-limited by default.

## Behaviour this product will not implement

* **No IP rotation to evade reputation systems.** Multi-IP support exists for legitimate
  separation — transactional versus subscription mail, tenant isolation, IPv4/IPv6 — not for
  escaping a poor reputation.
* **No retry storms.** When a destination defers or signals a rate limit, the per-domain
  channel *reduces* concurrency and *increases* spacing.
* **No circumvention of provider throttling.** When a receiver asks us to slow down, we slow
  down.

These are product boundaries, not defaults to be configured away.

## Warming a new IP

Start low — tens of messages a day — and grow gradually over several weeks. Send mail people
asked for. Handle bounces and complaints promptly. Publish `abuse@` and `postmaster@` and read
them.

There is no configuration setting that substitutes for this.
