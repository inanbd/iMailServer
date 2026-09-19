# Deliverability

> **Status: in progress — Milestone 11.** The check model and the score are built and
> tested; the checks that feed them are landing one group at a time.

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

### How the number is arrived at

**A warning is worth half its weight.** Full credit would make the score say nothing about a
configuration that is one bad day from failing. No credit would make a warning indistinguishable
from a failure, so an operator with a working setup and one soft-fail SPF record would see the
same number as one whose SPF is missing entirely — and would not know which to fix first.

**An inconclusive check lowers the ceiling, not the score.** A DNS timeout is not a fact about
the operator's configuration. Scoring it as a failure sends somebody to fix something that is
not broken; scoring it as a pass reports readiness the server has no evidence for. Its points
are therefore excluded from both the numerator and the denominator, and reported as *untested*.

**A category with no checks is entirely untested** — not perfect, not zero. Leaving the
reputation providers unconfigured neither awards ten points nor deducts them.

**Within a category, checks are weighted relative to each other** and the published share is
divided in that proportion. Two checks weighted 1 and 3 in a category worth 20 are worth 5 and
15. A check's weight stays a local decision: adding a seventh identity check does not require
re-deciding the other six, and the category totals remain exactly the numbers in the table above.

### Readiness is not the score

A report can score 94 with a failing SPF record if everything else is perfect, and 94 is a
comfortable-looking number that hides a configuration receivers will reject on the very first
message. So the verdict — **Ready**, **Not ready**, **Unknown** — is decided by the worst outcome
present and never by arithmetic, and the UI leads with it. Any failure is *Not ready*; any
inconclusive check is *Unknown*; a report with no checks at all is *Unknown* rather than *Ready*.

For the same reason, a partially judged report never leads with a number out of a hundred. One
passing check and eighty untested points rescales to 100%, and a sentence beginning "100 out of
100" is read as perfect however carefully it is qualified afterwards — by an operator skimming,
by a UI that truncates, by a screenshot. It reads *"20 out of the 20 points that could be judged;
80 of 100 were not tested"*.

## Authentication is weighted highest for a reason

SPF, DKIM and DMARC are the checks a receiver can evaluate on the very first message from an
unknown sender. Everything else — volume patterns, complaint rates, engagement — takes time to
accumulate. Getting authentication right is the part that is entirely within your control and
entirely verifiable before you send anything.

### The eight authentication checks

Implemented in `AuthenticationChecks` (Domain, pure). Sixteen points, normalised to the
category's thirty.

| Id | W | Judged on |
|---|---|---|
| `auth.spf-published` | 3 | Exactly one parseable `v=spf1` record |
| `auth.spf-policy` | 2 | The qualifier on the closing `all`, or a `redirect` |
| `auth.spf-lookup-budget` | 1 | Terms that cost a DNS lookup, against RFC 7208 §4.6.4's ten |
| `auth.dkim-published` | 3 | A usable key at some configured selector |
| `auth.dkim-key-strength` | 1 | RFC 8301 §3.2 — 1024 a MUST, 2048 a SHOULD |
| `auth.dmarc-published` | 3 | Exactly one parseable `v=DMARC1` record at `_dmarc` |
| `auth.dmarc-policy` | 2 | `p=`, and whether `pct=` applies it to everything |
| `auth.dmarc-reporting` | 1 | A `rua=` tag |

Four judgements in there are worth stating, because each is a place where the obvious reading is
wrong:

**Two SPF records is a failure, not a duplicate.** RFC 7208 §4.5: "If the resultant record set
includes more than one record, check_host() produces the 'permerror' result." The usual way to
arrive here is adding a second record for a new sending service — an operator who has just made
their mail *less* deliverable by configuring something, and who will not guess why.

**`+all` fails where `~all` warns.** `all` always matches (§5.1), so a leading `+` authorises the
entire internet to send as the domain. It is not a weaker policy than `~all`; it is the absence of
one, published in a form that looks like a policy.

**The first `all` decides, and it silences any `redirect`.** §5.1: "Mechanisms after 'all' will
never be tested. Mechanisms listed after 'all' MUST be ignored. Any 'redirect' modifier […] MUST
be ignored when there is an 'all' mechanism in the record, regardless of the relative ordering of
the terms." So `v=spf1 -all ~all` is `-all`, and a `redirect` beside an `all` costs no lookup
either — charging for it would send an operator to shorten a record already inside the limit.

**The lookup count is a floor, and the detail says so.** Each `include` spends the budget again
inside the record it fetches, so a domain at eight terms of its own may already exceed ten at a
receiver. The check therefore warns from eight rather than only at eleven, and the text names what
it counted: *"This counts only the terms in your own record."* A bare "9 of 10" reads as headroom
that is not there.

A revoked DKIM key — RFC 6376 §3.6.1's empty `p=` — is treated as no key at all, and named as
revoked in the evidence. A server signing with a revoked selector produces signatures every
receiver rejects, while DMARC alignment quietly falls back to SPF and keeps passing; nothing
visibly breaks until an SPF change, at which point the cause is weeks old. The weakest live key
decides the strength check, since a forger picks which selector to claim.

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
