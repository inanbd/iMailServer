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
category's thirty. `AuthenticationProbe` (Infrastructure) does the looking-up — three names, one
TXT query each: the domain, `_dmarc` beneath it, and `selector._domainkey.domain` per configured
selector. It carries back *every* TXT record at each name rather than the one that looks
relevant, because "two `v=spf1` records" is a finding and a probe that filtered would make it
undetectable. Choosing among records is a rule, and the rules are all in the Domain half.

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

## The TLS category

**Nothing in this category is required to carry mail, which is exactly why it scores twenty.**
RFC 3207 makes TLS between MTAs opportunistic — "A publicly-referenced SMTP server MUST NOT
require use of the STARTTLS extension in order to deliver mail locally" — so a server with no
certificate at all still exchanges mail with most of the internet. What it cannot do is satisfy
MTA-STS, DANE, or any mail client, and every one of those failures is silent from this side: the
sender's report shows it, the receiver's does not.

So the checks judge against RFC 8461 §4.2's bar rather than RFC 3207's — "The certificate
presented by the receiving MTA MUST not be expired and MUST chain to a root CA that is trusted by
the Sending MTA. The certificate MUST have a subject alternative name (SAN) [RFC5280] with a
DNS-ID [RFC6125] matching the hostname" — because that is the bar the senders who care apply.

`TlsChecks` covers the certificate and the listener (14 points); `TransportPolicyChecks` covers
the published policies (6).

| Id | W | Judged on |
|---|---|---|
| `tls.certificate-installed` | 3 | A certificate is bound to the SMTP listeners |
| `tls.certificate-covers-hostname` | 3 | RFC 8461 §4.2 — a SAN matching the EHLO name |
| `tls.certificate-trusted` | 3 | Chains to a trusted root; self-signed is its own finding |
| `tls.certificate-expiry` | 3 | Valid now, and outside the renewal window |
| `tls.renewal-health` | 1 | Auto-renew on, last attempt did not fail |
| `tls.starttls-offered` | 1 | STARTTLS advertised on 25 |
| `tls.mta-sts-record` | 2 | RFC 8461 §3.1 — one `v=STSv1` record, with an `id` |
| `tls.mta-sts-policy` | 2 | The resource is served, parses, covers the MX, and enforces |
| `tls.tls-rpt` | 2 | RFC 8460 §3 — a `_smtp._tls` record with `rua` |

**A self-signed certificate fails although mail keeps arriving.** That gap is the point. The
operator watching their queues sees nothing wrong; §5's enforce mode says senders "MUST NOT
deliver the message to hosts that fail MX matching or certificate validation", and the mail that
never arrives leaves no trace here. Self-signed is reported separately from a chain that merely
fails to build, because the remedies differ: one is a certificate to replace, the other is
almost always a missing intermediate the server does not send.

**A not-yet-valid certificate names the clock.** It is refused exactly as an expired one is, and
the cause is far more often this server's clock than the certificate — an operator told only
"not valid until" goes and reissues a perfectly good certificate.

**Renewal health is judged only for certificates this server can re-obtain.** A hand-installed
certificate has no renewal process, and inventing a finding about one would send an operator to
fix nothing. The expiry check still watches the outcome.

**The STARTTLS remedy says not to require it.** RFC 3207 again: requiring it on a
publicly-referenced server "damages the interoperability of the Internet's SMTP infrastructure".
A remedy reading "require TLS" would be telling the operator to break inbound mail in the name of
securing it.

**Two MTA-STS records fail where none only warns.** §3.1: "If the number of resulting records is
not one […] senders MUST assume the recipient domain does not have an available MTA-STS Policy
and skip the remaining steps of policy discovery." Publishing none is a choice; publishing two is
the same effect while the record on screen says otherwise.

**A record with no reachable policy is worse than neither** — every sender follows it, spends a
request per refresh and gets nothing, while the operator sees a correct TXT record. Each way the
fetch can fail is its own finding: unreachable, no policy at the path, a policy host whose
certificate is invalid (a browser that clicks through the warning shows the file perfectly), and
the wrong media type, which §3.2 has senders reject. The fetch happens only when a record says
there is a policy — otherwise this server would be making an outbound request to a host named by
the domain under test on the strength of nothing that domain published.

**A policy omitting a live MX host is the one MTA-STS fault that loses mail**, so it is reported
ahead of the mode. A testing-mode policy that omits an MX starts losing mail the moment the
operator follows the other finding and moves to enforce.

## The DNS category

The reverse question from Identity: not whether receivers accept what this server sends, but
whether anything arrives. A server can pass one completely while failing the other, which is why
the findings stay separate.

`DnsChecks` (Domain, pure) and `DnsProbe` (Infrastructure). Fifteen points:

| Id | W | Judged on |
|---|---|---|
| `dns.mx-published` | 4 | An MX record exists, and is not RFC 7505's null MX |
| `dns.mx-resolves` | 4 | RFC 5321 §5.1 — every target returns an address record |
| `dns.mx-not-alias` | 2 | RFC 2181 §10.3 — no target is a CNAME |
| `dns.mx-redundancy` | 1 | §5.1's "SHOULD try at least two addresses" |
| `dns.mx-points-here` | 2 | Some MX names this server |
| `dns.ttl-sanity` | 1 | 5 minutes to 1 day — advice, not conformance |
| `dns.caa-allows-issuer` | 1 | RFC 8659 — CAA does not forbid the ACME issuer |

**The SPF lookup limit is not here**, although the table above lists it under DNS. It is a
property of the SPF record rather than of the zone, an operator fixes it by editing that record,
and it is already `auth.spf-lookup-budget`. Scoring it twice would weight one fault at four
points across two categories and make the Authentication total mean something other than what it
says.

**No MX warns; a null MX fails.** §5.1: "If an empty list of MXs is returned, the address is
treated as if it was associated with an implicit MX RR, with a preference of 0, pointing to that
host." So a domain with no MX does receive mail — wherever its A record points, which for many
domains is a web server that refuses it. Calling that a failure would be wrong about the
mechanism; calling it a pass would hide the dependency. RFC 7505's `0 .` is different in kind: an
explicit refusal to accept mail, and assessing a mail server for a domain that publishes one is a
contradiction worth naming. A null MX is then excluded from every check that judges *routes* —
counting "." as a route would produce three more findings, all restating the first.

**An aliased MX fails rather than warns.** RFC 2181 §10.3 forbids it outright, and §5.1 says the
behaviour "lies outside the scope of this Standard" — so each sender decides for itself, the loss
is partial and intermittent, and it gets attributed to anything but DNS.

**`dns.mx-points-here` warns and never fails.** A filtering service or relay in front is a real
architecture whose DNS is indistinguishable from an operator who built a mail server and never
pointed the domain at it. The check describes the arrangement and lets them recognise their own.

**The TTL check says in its own text that no RFC sets a range.** RFC 2181 §8 defines a TTL as "an
unsigned number, with a minimum value of 0, and a maximum value of 2147483647" and stops there;
every value conforms. What is left is a trade between the lookups a short TTL costs and the delay
a long one adds to a correction — so both ends warn, neither fails, and an operator mid-migration
is told what a low TTL costs rather than that they are wrong.

**CAA is a mail check because of what it breaks.** A renewal the CA refuses ends in an expired
certificate, and that ends STARTTLS, MTA-STS and every receiver requiring them — sixty days after
the record was published, when nobody connects the two. The probe walks up the tree as RFC 8659
§3 requires, because a restriction published once at the registered domain and forgotten is the
case that catches people. Absence of CAA is a pass: §4 makes a restriction exist only where an
RRset does.

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

`IReputationProvider` is an abstraction with caching and rate limiting. `DnsBlockListProvider`
implements it over `IDnsDiagnosticsService`; `ReputationChecks` judges what it returns.

Naïve DNSBL querying from a busy MTA gets you blocked by the DNSBL operator and is an abuse of
volunteer infrastructure. Results are cached for fifteen minutes and queries to one zone are
spaced two seconds apart. A delisting takes hours to days to take effect, so a fresher answer
buys an operator nothing and costs the list a great deal.

**No list is configured by default, and that is not an omission.** Querying a list is a request
this server makes, on the operator's behalf, to an organisation they have not chosen; several
forbid automated use without an arrangement. `MailServer:Deliverability:BlockLists` is empty
until they fill it.

### The self-test, and why it is the important part

RFC 5782 §5: "IPv4-based DNSxLs MUST contain an entry for 127.0.0.2 for testing purposes.
IPv4-based DNSxLs MUST NOT contain an entry for 127.0.0.1." Domain lists get RFC 2606's `TEST`
and `INVALID` instead.

Every list is asked those two questions before it is asked anything real, because **a list that
has stopped serving this server commonly answers "listed" for every query it is given** — which
is what a public resolver or an exceeded free-use quota looks like, and which is indistinguishable
from a genuine listing. Believing it would send an operator to file delisting requests with
several organisations for a problem they do not have.

So a verdict from a list that failed its self-test is not counted. It is not silently dropped
either: `reputation.lists-usable` reports it, with a remedy pointing at the resolver rather than
at anything the operator publishes, because nothing they publish can change it. And with no
believable list at all the verdict is *Unknown*, never *clean* — "nobody listed you" and "nobody
answered" are different facts and only one is good news.

| Id | W | Judged on |
|---|---|---|
| `reputation.ip-not-listed` | 6 | The sending address, on lists that passed their self-test |
| `reputation.domain-not-listed` | 3 | The domain, likewise |
| `reputation.lists-usable` | 1 | RFC 5782 §5's test entries |

Ten points, the second lowest, deliberately. Everything else in this report is something the
operator controls and can verify before sending a message; a blocklist entry is somebody else's
judgement, arrives after the fact, and is often about the previous tenant of an address.

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
