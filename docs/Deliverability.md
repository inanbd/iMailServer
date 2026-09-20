# Deliverability

> **Status: built and tested — Milestone 11.** All six check categories are implemented and
> wired into `DeliverabilityReportService`, the score is computed over them, and the header
> analyser, the DNS wizard, the delivery test, MTA-STS policy publishing and TLS-RPT collection
> are covered by tests and reachable over IPC. The admin console has a Deliverability view that
> renders the report with the evidence for every check — this milestone's exit criterion.
>
> **Two things to know.** The report has **never been run against a live Internet exchange**:
> every check here is exercised against this product's own tests and the RFC text, the same
> caveat `docs/Standards.md` records for the mail-authentication work. And the admin view is
> **written but not yet run** — it is a WPF binary, so it builds on this repository's Linux CI
> and can only be opened on Windows. `docs/Verification.md` is the checklist for that run.

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

## Running the report

`IDeliverabilityReportService` runs every probe once and judges everything they gathered.
`DeliverabilityRunOptions` decides what a run is allowed to do: `Full` does everything, `DnsOnly`
makes no SMTP connection, no HTTPS request to a policy host and no query to a third-party list.
The checks those would have fed report as not tested, which the score already carries — and the
summary leads with the real denominator rather than rescaling a handful of checks to a hundred.

**One run, one report.** Two data dependencies make the order matter, and both are real:

* The **MX hosts** come out of `DnsProbe` and are what an MTA-STS policy's `mx` list is judged
  against. Resolving them a second time would let the two halves of one report disagree about
  what the domain publishes — and the disagreement would surface as a finding about the policy
  rather than as the inconsistency it is.
* **STARTTLS** comes out of the relay test's EHLO answer, which is already on the wire. One
  connection, two findings; a second probe would open another connection to read a line this one
  already has.

**A probe that throws does not take the report with it.** Each category is gathered inside a
boundary that turns a failure into no facts. An operator with one unreachable nameserver gets the
ninety points that were measurable, not an error page. Cancellation is the exception and is
rethrown: the caller asked for the run to stop, and turning that into "the probe failed, here are
ninety points" would hand back a report they no longer wanted.

**Only active DKIM keys count as this server's selectors.** A retired key's selector may still be
published on purpose so signatures made before the rotation still verify; reporting it would make
a completed rotation look like a configuration to fix, and would start failing once the grace
window ended and the record was withdrawn.

### The chain build, and revocation

`tls.certificate-trusted` needs a chain built against the certificate the provider would actually
hand a listener — the fault it catches is an intermediate the server does not send, which is
invisible in stored metadata.

**Revocation is checked, not skipped.** RFC 8461 §4.2 lets a sending MTA check the receiving
one's certificate for revocation, so a revoked certificate is a real deliverability failure and
one an operator would rather hear from their own report than from a receiver. The cost is a
network round trip, which a diagnostic run on demand can afford where a handshake could not.
(`docs/Standards.md` rule 105 forbids certificate-validation bypasses, and a security test
enforces it against every production source file — which is how this was caught.)

That makes the chain's outcome four states rather than two, because three of them have different
remedies: **self-signed** is a certificate to replace, **untrusted** is almost always a missing
intermediate, and **revoked** has to be reissued and is urgent — and if the operator did not ask
for the revocation, the private key is the real news.

**Revocation that could not be determined is not a broken chain.** An unreachable CRL or OCSP
endpoint fails the build with nothing but `RevocationStatusUnknown` or `OfflineRevocation` to
show for it. The chain itself built; only its revocation state is unknown. Treating that as
untrusted would send an operator to reinstall intermediates that were never missing — and it
would happen to everyone whose outbound network blocks OCSP, which is a great many people.

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

## Reaching it

Four IPC commands, three of them read-only:

| Command | Request | Returns | Permission |
|---|---|---|---|
| `Deliverability.Report` | domain, plus three run switches | `DeliverabilityReportDto` | `ViewServerState` |
| `Deliverability.AnalyseHeaders` | pasted headers, optional client address | `HeaderAnalysisDto` | `ViewServerState` |
| `Deliverability.DnsPlan` | domain, plus three operator choices | `DnsPlanDto` | `ViewServerState` |
| `Deliverability.DeliveryTest` | sender, recipient, TLS policy | `DeliveryTestDto` | `ManageQueue` |

The first three ask for `ViewServerState`, not `ReadMessageContent`. The report reads this
server's own configuration and public DNS; the analyser reads headers the operator pasted into
the request; the plan reads configuration and the DKIM key's **public** half. None opens a
stored message, which is the boundary `ReadMessageContent` exists to guard — and the moment one
did, it would need that permission instead.

**The delivery test asks for `ManageQueue`, and that difference is the point.** It is the only
command here that makes this server send mail to a third party, and `ManageQueue` is the
permission that already governs exactly that power — retrying a queued item causes a send in the
same way. Asking for `ViewServerState` would let anyone who can read a graph send mail from the
operator's domain; adding a permission of its own would claim this is a power the existing set
does not already cover, and it is. It is also the only one of the four that is a *command*
rather than a query: calling it a query would put an outward-facing side effect behind the word
"read".

**The run switches are on the request rather than in configuration** because they decide what
this server does to other people: whether it opens an SMTP connection to itself, fetches a policy
from a host the domain under test names, and queries third-party blocklists. An operator who
wants none of that can ask for none of it.

`HeaderAnalysisDto` has no DKIM pass or fail field, only `DkimCouldAlign`, and a test asserts the
shape rather than a value — a property called anything like `DkimPass` would be a promise a
header block cannot keep, and the name is the safeguard. Each signature is paired with its own
selector's lookup by name, never by position: a signature that fails to parse is never looked up,
so a positional join would attribute the next signature's key state to it and report a published
key for a selector that has none.

## DNS wizard

The report says what is wrong. The wizard says what to publish — and an operator with nothing
published yet needs the second first, because the report's answer for them is a score of zero and
a list of failures.

`Deliverability.DnsPlan` returns every record for one domain, each with the reason it is being
asked for, plus the zone-file text for an operator who would rather paste than click. It reads
DNS not at all and writes it never: this product holds no credentials to any registrar, and the
plan is advice for a person to check.

### What it proposes

For `example.com` on `mail.example.com` at `203.0.113.10`, with a key generated and reporting
addresses chosen:

```text
mail.example.com.               IN A    203.0.113.10
example.com.                    IN MX   10 mail.example.com.
example.com.                    IN TXT  "v=spf1 mx ip4:203.0.113.10 -all"
mail2026._domainkey.example.com. IN TXT "v=DKIM1; k=rsa; p=…" "…"
_dmarc.example.com.             IN TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
_mta-sts.example.com.           IN TXT  "v=STSv1; id=20260919T120000;"
_smtp._tls.example.com.         IN TXT  "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
; 10.113.0.203.in-addr.arpa.    IN PTR  mail.example.com.
```

**Owner names are absolute and end with a dot.** A relative name pasted under the wrong `$ORIGIN`
becomes `_dmarc.example.com.example.com` — which resolves, answers nothing, and looks right at a
glance.

**The reverse record is commented out, not omitted.** It is not the operator's to publish, and
every record carries which zone it belongs in so a UI can say so. Leaving it out entirely would
let an operator think the plan had forgotten reverse DNS; leaving it in uncommented would have
them publish it into their own zone, where it does nothing.

### The three choices

`DmarcReportAddress`, `TlsReportAddress` and `MtaStsId` are on the request because each is a
decision rather than a fact. Where reports go is a mailbox somebody has to read, and advertising
an MTA-STS policy commits the operator to serving one over HTTPS for as long as the record
stands. Defaulting them would put records in front of an operator that look like this server's
findings rather than their own choices. Omitting one leaves its record out of the plan — except
DMARC, where a record with no `rua=` is still proposed and flagged as a policy published blind.

### The traps it exists to catch

**A DKIM key does not fit in one TXT string.** RFC 1035 §3.3.14's `character-string` is a length
octet and up to 255 more, and a 2048-bit key's base64 is around 392 characters. The plan splits
it and says so, because some providers take the strings in one field, some want them quoted and
separated, and a few silently truncate — and a truncated key parses and verifies nothing. The
split is positional and needs no token awareness: RFC 6376 §3.6.2.2 has readers concatenate
"with no intervening whitespace", and RFC 7208 §3.3 says the same for SPF. It is a limit on
octets, so a character is never cut in half to reach it.

**Reports addressed outside the domain need the receiver's permission.** RFC 7489 §7.1: a
receiver that finds `rua=` pointing outside the policy's own organizational domain must query
`{policy-domain}._report._dmarc.{reporting-domain}`, and "Where the above algorithm fails to
confirm that the external reporting was authorized by the Report Receiver, the URI MUST be
ignored". An operator who points `rua=` at a third-party service and publishes nothing else gets
silence, with no error anywhere to explain it. The plan names the exact record the other domain
must publish. The comparison is by organizational domain, not by name, so
`rua=mailto:dmarc@example.com` on `mail.example.com` is not flagged.

**An MTA-STS id is alphanumeric and at most 32 characters.** RFC 8461 §3.1:
`sts-id = %s"id=" 1*32(ALPHA / DIGIT)`. `20260919T120000` fits; the same timestamp with
separators does not, and a record carrying one is discarded by every sender. The plan refuses to
propose it and quotes the grammar instead.

**The MX target must not be a CNAME.** RFC 2181 §10.3: "The domain name used as the value of a NS
resource record, or part of the value of a MX resource record must not be an alias." It works
with some senders and not others, which is the worst way for a configuration to be wrong.

**`p=none` is where DMARC starts, and the plan says what comes next.** The readiness report warns
about the same value, and the two agree: that check's own text calls it "the right setting while
you are reading reports" and its remedy is the next step rather than a different starting point.
An operator who follows this plan and then runs the report is not told they were misled.

## Delivery test

> Built. `DeliveryTestService` sends down the production path — the same resolver, the same MX
> selection, the same outbound client with the same DKIM signing as ordinary mail — and adds a
> stopwatch and a transcript. It sends straight rather than through the queue, because an
> operator running a diagnostic wants to know what happened now rather than have a failure
> retried quietly for six hours.

Sends a real message to an address you nominate and records the whole conversation:

```text
     0ms   [Connect] mx.example.net:25 [203.0.113.9]
    40ms < 220 mx.example.net ESMTP ready
    80ms > EHLO mail.example.com
    82ms < 250 mx.example.net
    82ms < 250-SIZE 52428800
    82ms < 250-STARTTLS
   120ms > STARTTLS
   122ms < 220 Ready to start TLS
   180ms   [Handshake] Tls13, subject CN=mx.example.net, chain trusted
   220ms > EHLO mail.example.com
   260ms > MAIL FROM:<postmaster@example.com>
   262ms < 250 OK
   300ms > RCPT TO:<someone@example.net>
   302ms < 250 OK
   340ms > DATA
   342ms < 354 End data with <CRLF>.<CRLF>
   380ms   [Body] 612 octets sent, DKIM-signed
   900ms < 250 2.0.0 OK 1758362400 - gsmtp
```

Sending to a Gmail account and reading the `Authentication-Results` header it adds is the
fastest honest answer to "is my setup correct?" — it is the receiver's own verdict rather than
our opinion of it.

**Recorded on the real delivery path, not a copy of it.** The same `OutboundSmtpClient` the queue
uses fills the transcript in, because a client written to be observable would be a second
implementation of MX selection, STARTTLS policy, DKIM signing and dot-stuffing — and a test of
that one would prove nothing about the one that carries the mail. The transcript is an optional
argument on the delivery request, null for every queued attempt.

**The recording happens where the command is sent**, in one place, so a command added to the
conversation later appears in the transcript without anybody remembering to put it there. A
transcript missing a command is worse than no transcript: an operator reading one trusts that
what is not in it did not happen.

**The message body is never in the transcript, and that is a rule rather than an omission.** A
transcript is read under `ViewServerState`; message content is guarded by `ReadMessageContent`.
A transcript carrying body octets would be a way to read mail with the weaker of the two
permissions, so the body step records how many octets went out and nothing else. The test that
pins this sends a distinctive string, checks the fake receiver really got it, and then asserts
its absence from the whole rendering rather than from the body step alone — the leak this guards
against would be somewhere nobody thought to look.

**Where it stopped is the diagnosis.** A conversation that ended at `RCPT TO` was refused the
recipient; one that ended at `MAIL FROM` was refused the sender, which is usually SPF or a
blocklist; one that ended at the banner never got to speak; and one with only a `Connect` step
never opened at all — which is what a blocked port 25 looks like, and the most common outcome of
a first delivery test.

**The capabilities reported are the ones learned after the handshake.** RFC 3207 §4.2 has the
client discard everything it learned before it, so the pre-TLS list is not what the conversation
ran on — and it is the list a network attacker can edit. The same rule decides the greeting
reported when a receiver refuses `EHLO` and the client falls back to `HELO`: the second one is
what the session ran on, so a refusal's own continuation lines are never reported as
capabilities the session had.

**Elapsed is measured from the first step, not from the previous one.** What an operator is
looking for is which single stage took the time, and a greylisting receiver that pauses before
its `RCPT TO` reply shows up as a jump in the column.

### What it sends, and to whom

**One message, one recipient, no repeat count.** Anything that took a list would be a tool for
sending unsolicited mail from an authenticated session, and the feature's value is one
conversation an operator reads.

**The sender is required, never defaulted.** It decides which domain's SPF, DKIM and DMARC the
receiver is about to judge, so a default would test a domain nobody asked about.

**The message is real and says what it is.** The receiver has to apply its ordinary rules to it,
so anything malformed would be judged as malformed rather than as this server's configuration.
It carries `Auto-Submitted: auto-generated` (RFC 3834), without which a receiver running an
out-of-office responder answers it — and the answer goes to whatever address the test was sent
from, which may be a mailbox nobody reads, or a loop. The body says who sent it, why, and that
no reply is needed, because whoever receives it may be on a mailbox the operator does not
control and an unexplained message is indistinguishable from a probe by a stranger.

**`TLS required` is off unless asked for.** The ordinary question is "does my mail arrive", and
answering it with a policy failure the operator did not ask for would hide the answer.

### How it delivers

**Every step is the one the queue takes**: the same resolver for MX, the same ordering policy,
the same client, the same port from the same options. What differs is that this one carries a
transcript and is not driven by a queue item.

**It tries the exchangers in turn and stops at the first that accepts**, exactly as the queue
does. Reporting only the primary would tell an operator whose primary is briefly down that their
mail cannot be delivered, when the queue would have used the secondary without comment. Every
attempt keeps its own transcript, because the conversation worth reading is usually the one that
failed.

**Nothing retries.** The queue's job is to keep trying; this one's is to say what happened once,
so a temporary refusal is reported as one rather than hidden behind a backoff nobody is
watching.

**A failed MX lookup is classified the way the queue classifies it** — a `SERVFAIL` deferred, an
`NXDOMAIN` or a null MX bounced. Conflating them is how a domain that does not exist earns an
infinite retry loop, or a resolver blip bounces good mail. See `docs/DNS.md`'s failure-semantics
table.

**The test message is stored, sent and then removed**, in that order. The client streams the
body from the store during `DATA`, so removing it any earlier would fail the send on a message
this server composed itself; leaving it behind would grow the store by one message per run. The
removal happens even when the send throws, and a store that cannot delete it logs a warning
rather than replacing a good answer with an unrelated error.

**There is no queue latency, because there is no queue.** The test connects and sends: the value
is seeing the conversation now, and a queued test would answer "submitted" and leave the
operator watching a queue.

**The DKIM selector reported is the one that actually signed**, read from the transcript's body
step. Only the signer knows which key it used, and a caller that looked the domain's active key
up for itself would be a second source for one fact — disagreeing the moment a rotation landed
between the two reads.

## TLS reports

> **Built.** Reports are collected from the `rua` mailbox, parsed and analysed. Collection is
> **off by default** — it needs the `_smtp._tls` record published and a mailbox here for the
> address to deliver into.

RFC 8460 has senders deliver a JSON report to the address in your `_smtp._tls` record, describing
the TLS sessions they had with you over a period — how many succeeded, how many failed, and why.

**It is the only feedback channel in this product that reports a real handshake from a real
sender.** A certificate that validates perfectly on this host and fails at Google is invisible to
every other check here, and is exactly what a report tells you.

`TlsReportReader` parses §4's JSON and `TlsReport` does the analysis: failures are grouped by
result type, ordered by the sessions each one cost, and given a remedy. The grouping matters
because a sender reports per MX host and per sending address, so one expired certificate arrives
as a dozen entries that are all the same problem.

**Several result types are not your fault, and the remedies say so.** `dane-required` is the
sender's own policy and `dnssec-invalid` is about your zone's signing — an operator reading every
entry as a defect in their mail configuration would go looking for a problem that is not there.

**Reports are unauthenticated.** Anyone who can reach the `rua` address can send one, and nothing
in RFC 8460 proves the organisation named actually sent it. Read them, act when several
independent senders agree, and never treat one as grounds on its own to change a policy.

**How collection works.** Point `MailServer:Deliverability:TlsRpt:ReportMailbox` at the address
in your `_smtp._tls` record and enable it. Every six hours the collector makes a bounded pass over
that mailbox, opens what it has not seen before, and files what it finds.

**It reads that mailbox and never changes it.** Nothing is marked seen, moved or deleted — a human
may be reading the same folder, and a collector that marked its own reading would fight them for
the unread count. What has been examined is recorded separately, so pointing it at a mailbox
somebody uses is safe.

**Failures are recorded too, and that is deliberate.** A bounce, a covering note or somebody's
reply will sit in that mailbox forever. A collector that only remembered its successes would open
and reject each of them on every pass for the life of the installation.

**A report is filed under the domain whose `rua` address received it**, never the policy-domain
the sender wrote in the report. Taking the sender's word would let anyone who can reach the
address file a report against any domain this server hosts.

Three sizes in a report message are a stranger's choice — the MIME part, the transfer encoding and
the compression — so each is bounded separately. A small attachment that decompresses to gigabytes
is the classic version of this attack, and a bound on the attachment alone would not catch it.

A report can still be submitted by hand, which is the route to use before the record is published
or when somebody forwards you one.

## Header analyser

Paste raw headers. The analyser **re-evaluates SPF, DKIM and DMARC itself** — its own DNS
lookups, its own reasoning, never the message's own claims about them — and shows the `Received`
chain with per-hop delays, `Return-Path`, `Reply-To` and `List-Unsubscribe`.

Useful in both directions: diagnosing why your mail was refused, and diagnosing why something
arrived that should not have.

**It never reads an `Authentication-Results` header, and this is the point rather than a
limitation.** An analyser that echoed back `dmarc=pass` from a header the sender wrote would be
reporting the forgery as a finding. `docs/DMARC.md`: "Trusting an attacker-supplied
`Authentication-Results: dmarc=pass` header is a complete authentication bypass, and it is
trivially easy to do by accident." RFC 8601 §7.1 says the same to consumers: results "should be
ignored, at least for the purposes of enacting filtering decisions, unless specifically enabled
by the user or administrator after verifying that the border MTA is compliant".

For the same reason **DKIM is reported as what was signed and by whom, not as pass or fail**. A
pasted header block has no body, and a body hash cannot be checked without one. What the analyser
can establish — and does — is whether the selector's key is published, whether it is usable, and
whether the signing domain lines up with `From`.

**ARC is deliberately absent.** `NoUntrustedAuthenticationHeaderTrustTests` allows exactly one
production file to touch the ARC types, and its own comment explains why the check scans for the
type names and not just the header text: "A hypothetical bridge file that reads
`ArcSet.AuthenticationResults.ResultsText` and string-searches it for a result token would
reference none of the four header-name literals". A display surface in the analyser is that
bridge file. Showing an ARC chain is worth less than the boundary that stops one from being
built by accident, so the analyser does not show one; `ArcChain` remains groundwork with no
consumer.

### What it reports

| From | Judged by |
|---|---|
| `Received` chain | `ReceivedTrace` — clauses per RFC 5321 §4.4, per-hop delays, and an ambiguity flag |
| `From`, `Return-Path`, `Reply-To` | Read as addresses; a `Return-Path` that differs from `From` is where SPF and DMARC part company |
| `List-Unsubscribe` | Present, and whether it offers the one-click POST RFC 8058 defines |
| `DKIM-Signature` | `DkimSignatureTags` — selector, `d=`, algorithm, signed headers, `t=`/`x=` |

### What it establishes for itself

`HeaderAnalysisService` takes what the block says and checks it against DNS.

**SPF is checked for the `Return-Path` domain, never `From`.** RFC 7208 §2.2: "Without explicit
approval of the publishing ADMD, checking other identities against SPF version 1 records is NOT
RECOMMENDED because there are cases that are known to give incorrect results. For example, almost
all mailing lists rewrite the 'MAIL FROM' identity […] but some do not change any other
identities in the message." Checking `From` is that mistake, and it is the one that makes every
forwarded message look forged.

**The address SPF is checked against is the operator's if they supply one, and the topmost trace
hop's otherwise — flagged either way.** An address from the message's own trace was written by a
host the operator may not control. Using it beats refusing to evaluate; presenting the result
without saying where it came from would let a forged trace header produce a confident pass.

**DKIM is never reported as passing.** RFC 6376 §3.7 hashes the body and a paste has none, so a
signature over a modified body looks identical here. What is established is whether the selector's
key is published and usable and whether its `d=` aligns — whether the signature *could* have
helped. The field is called `DkimCouldAlign` for that reason, and a signature whose key is not
published cannot align however well its `d=` matches: alignment is about which domain is
authenticated, and a signature nobody can verify authenticates none.

**Alignment follows the record's own `adkim=`/`aspf=`.** RFC 7489 §3.1.1: "In relaxed mode, the
Organizational Domains of both the [DKIM]-authenticated signing domain […] and that of the
RFC5322.From domain must be equal[…] In strict mode, only an exact match between both of the
Fully Qualified Domain Names (FQDNs) is considered to produce Identifier Alignment." The policy
itself is discovered at the From domain, per §6.6.3 — looking it up at the Return-Path would
find nothing for most bulk mail, and the analyser would then apply relaxed defaults to a domain
that asked for strict.

**When neither leg can align, the analyser says DMARC cannot pass.** That is the most useful
sentence the tool produces for "why was my mail refused": both legs are ruled out, so no amount
of receiver-side variation changes the answer.

A temporary lookup failure is never reported as a missing record. Telling an operator to
republish something that is already there wastes their time and leaves the real fault unfound.

The `Received` chain's per-hop delays exist because RFC 5321 §4.4 asks for them: "As the Internet
grows, comparability of Received header fields is important for detecting problems, especially
slow relays." Every delay is a difference between two independent clocks, so a negative one is
reported rather than clamped — it is the only evidence in the header block that one of those two
hosts has its clock wrong.

## The Operations category

Five points, the lightest of the six, and it contains the single worst finding in the report.

| Id | W | Judged on |
|---|---|---|
| `operations.not-an-open-relay` | 3 | An unauthenticated message to an outside address is refused |
| `operations.queue-health` | 2 | The **age** of the oldest queued message |
| `operations.bounce-rate` | 2 | Permanent failures as a share of recent deliveries |
| `operations.disk-space` | 2 | Free space on the message store's volume |
| `operations.clock-skew` | 1 | Distance from an external time reference |

The weights are relative; `DeliverabilityReport.From` normalises them to the category's five, and
a test asserts that rather than the arithmetic.

**An open relay is not a five-point problem, and the weight does not have to say so.** Readiness
is the worst outcome present and never the arithmetic, so a server scoring 96 with an open relay
is *Not ready* and the UI leads with that. This is the design working as intended: it is why the
verdict and the score are separate things. The remedy says to take the listener off the network
before changing any setting, because while it is reachable it is being used.

**The queue is judged on age, not depth.** A queue of ten thousand that clears in a minute is a
busy server; a queue of one that has been there since yesterday is a broken one. A check on depth
reports the first and misses the second. A non-empty queue whose age is unknown is therefore
*Inconclusive* rather than passing — depth alone says nothing about health.

**A bounce rate is not computed below fifty deliveries.** Two bounces out of three is 67% and
means nothing; an operator on their first day would otherwise be shown a catastrophic number
generated entirely by their own test messages, and would go looking for a problem that does not
exist.

### Gathering the operations facts

`OperationsProbe` reads the queue, the disk and the clock; the open-relay self-test is passed
*in*, because it is the one part that opens a connection and a caller who cannot reach the
listener — or should not, on a host where port 25 is not this server's — must be able to leave it
out.

**`OpenRelaySelfTest` stops at `RCPT TO` and never sends `DATA`.** The answer to that one command
is the entire finding, and a test that went on to submit a message would be a test that sends
mail — from a server whose whole problem, if the test fails, is that it sends mail for strangers.
Both addresses are in RFC 2606's reserved `.invalid`, "intended for use in online construction of
domain names that will surely fail", so even an accepted recipient has nowhere to go. `RSET`
precedes `QUIT`, and the client waits for the `221` (RFC 5321 §4.1.1.10) rather than hanging up.

**A test that did not complete is `null`, never `false`.** A refused connection, or a sender the
server rejected before the recipient was ever asked about, says nothing about what it does with
a conversation it accepts. Reporting either as "not an open relay" would be the most dangerous
false pass in the report.

**An acceptance here means something specific.** `RelayPolicy` has no implicit trust for any
address — local domains, authenticated submission, and a list an operator typed are the only
three ways through — so this is not the usual "many servers trust localhost" false positive. The
finding names the address it tested from, because an acceptance means that address is on the
authorised relay list, and seeing which address tells a deliberate entry from an accident.

**`SntpTimeReference` is read-only.** Its result reaches one check and stops. A mail server that
took its time from an unauthenticated UDP packet would hand whoever can answer it the ability to
expire its own certificates and invalidate its own signatures. It is thirty lines of RFC 4330
rather than a package: a 48-octet request, and the transmit timestamp at octet 40 read against
the 1900 epoch. An all-zero timestamp is §4's "unknown or unsynchronised", not the year 1900.

**The clock check names what a skew breaks** — DKIM signatures carrying `x=`, a new certificate
that looks not-yet-valid, `Received` headers dated wrongly — because none of those looks like a
clock problem from the outside, and an operator told only "your clock is wrong" has no reason to
connect it to the delivery failures they are chasing. A clock behind is judged exactly as one
ahead; reading the signed value rather than its magnitude would pass every slow clock in the
world.

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
