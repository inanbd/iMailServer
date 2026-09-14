# Let's Encrypt and ACME

> **Status: Milestone 4 complete, with one honest gap.**
>
> Built and tested: account registration, order creation, HTTP-01 and DNS-01 challenges,
> bounded validation polling, CSR and chain download, storage, binding, hot reload, automatic
> renewal at 30 days, rate-limit enforcement and pre-flight checks.
>
> **Not verified against Let's Encrypt itself.** Issuance needs a publicly resolvable domain
> and inbound port 80 — no build agent has either. The issuance sequence is tested end to end
> against a fake certificate authority at the `IAcmeClient` seam, and the live staging
> directory endpoint was fetched by hand to confirm the client reaches it. What remains
> unproven is Certes talking to Let's Encrypt for a real order. See
> [What is and is not proven](#what-is-and-is-not-proven).

Automatic, free, publicly trusted certificates via ACME v2 (RFC 8555), using the **Certes**
library. Hand-implementing ACME's JWS signing, nonce handling and key-authorisation digests
would be an unnecessary cryptographic risk for the one component that handles the account key.

## What is and is not proven

| | |
|---|---|
| **Proven by test** | Pre-flight refusal, rate-limit refusal, order creation, challenge publication, challenge cleanup on every path including failure, certificate storage, binding, the renewal filter, and every failure path's effect on the recorded order |
| **Proven by hand** | The Let's Encrypt staging directory is reachable and parses; Certes 3.0.4 generates and round-trips ES256 and RS256 keys on .NET 10 |
| **Not proven** | A real order against Let's Encrypt. This needs a public DNS name resolving to the machine and inbound TCP 80 — neither of which a build agent has |

The gap is stated rather than hidden because §106 forbids claiming compliance before
functionality has tests, and a test that pretended to cover this would be worse than none. The
first real issuance will happen on an operator's server, which is why **staging is the default**
and why the pre-flight and rate-limit checks matter as much as they do.

---

## Requirements before you start

| For HTTP-01 | For DNS-01 |
|---|---|
| Public DNS A/AAAA pointing at this server | Control of the domain's DNS |
| **Inbound TCP 80 reachable** | An API-capable DNS provider, or willingness to do it by hand |
| | Would be required for wildcards, which are [not supported yet](#wildcards) |

Port 80 is the usual stumbling block. If it is blocked upstream, use DNS-01.

## First issuance

```text
1. Create or load the ACME account key      (DPAPI-protected, never logged)
2. Register the account, accept the ToS, set a contact address
3. PRE-FLIGHT: does DNS point here? is :80 reachable?   ← fail here, not at the CA
4. Create an order for the identifier set
5. Fetch authorisations, select a challenge
6. Publish the challenge, ask the CA to validate, poll with bounded backoff
7. Generate a NEW key pair (never reuse), build the CSR, finalise
8. Download the chain
9. Validate: chain builds, hostname matches, private key present and usable
10. Persist, update the binding, hot-swap
11. Audit; clean up the challenge artefact — always, including on failure
```

Step 3 exists because a misconfiguration caught locally costs nothing, while the same
misconfiguration discovered at the CA costs a failed-validation rate-limit slot.

## Challenges

**HTTP-01** — the service serves the token from Kestrel:

```text
http://mail.example.com/.well-known/acme-challenge/{token}
```

**DNS-01** — a TXT record at `_acme-challenge.example.com`, published through
`IDnsChallengeProvider` and then polled until it propagates. It should be polled at the
**authoritative** nameservers; checking a recursive resolver can report success before the CA
can see it. See [Propagation checking](#challenges) below for where that stands today.

No DNS provider is hardcoded into the architecture. Cloudflare, Route 53, Azure DNS,
DigitalOcean, GoDaddy, Namecheap and a generic webhook are all provider modules behind the same
interface.

**Manual DNS-01** is a first-class implementation, not an error path. Plenty of domains are
hosted somewhere with no usable API, and treating that as a failure would exclude them from
automation entirely. The UI shows the exact record to publish, and **the order stops there** —
the certificate authority is not asked to validate until the operator requests again. That
ordering is what protects the five-failures-per-hostname-per-hour limit from someone pressing
the button before the record exists.

**Propagation checking** uses a small DNS client written for this purpose, because the BCL has
no TXT lookup at all — `System.Net.Dns` resolves names to addresses and nothing else. Without
it the "check" would report failure for a correctly published record, which is worse than not
offering one.

It queries the resolvers in `MailServer:Acme:ChallengeCheckResolvers` and counts the record as
published only when **all** of them return it. Those should be the zone's authoritative
nameservers; resolving that set needs NS and SOA handling that belongs with the full resolver in
Milestone 9, so for now they come from configuration and default to public recursive resolvers.
A recursive resolver can serve a cached negative answer after a record is live, so a check that
says "not yet" is worth repeating.

## Rate limits — read this before troubleshooting

Let's Encrypt production limits that matter:

| Limit | Value |
|---|---|
| Certificates per registered domain | 50 per week |
| Duplicate certificates | 5 per week |
| Failed validations | 5 per account, per hostname, per hour |

**New installations default to the staging directory**, and switching to production is a
deliberate configuration change. This is not caution for its own sake: an operator fixing DNS
while retrying against production exhausts the five-duplicates-per-week limit in an afternoon
and then waits a week with nothing to show for it.

The limiter tracks attempts in the `AcmeOrders` table and **refuses** an order that would breach
a documented limit, saying which limit and when it clears. Three details make the difference
between a limiter that helps and one that gets in the way:

* **Only attempts that reached the CA are counted.** An order refused by pre-flight or by the
  limiter itself never reached the CA and consumed no quota; counting those would make the
  server progressively more reluctant to do something that has cost nothing — a limiter that
  ratchets itself shut.
* **Failed validations are reported before the duplicate limit.** An operator who has hit both
  needs to hear about the failures, because that is the one they caused and the one they can
  fix.
* **One slot of headroom.** The local count can disagree with the CA's — a certificate issued
  for the same domain by another tool counts against theirs and not ours — so stopping one short
  turns a disagreement into a local message rather than a spent slot.

Grouping by *registered domain* uses a heuristic, not the Public Suffix List, which arrives in
Milestone 9 for DMARC alignment. The heuristic over-groups in the cases it gets wrong, which
makes the limiter refuse earlier than the CA would — the safe direction.

Staging certificates are **not publicly trusted**. That is the point — they prove the flow
works without spending production quota.

## Renewal

`CertificateLifecycleService` checks every 12 hours.

```text
≤ 30 days remaining  → attempt renewal
≤ 21 / 14 / 7 days   → escalate health severity at each threshold
failure              → keep the existing certificate, back off, alert
                       NEVER downgrade to self-signed
```

Thirty days is deliberate: Let's Encrypt certificates last 90, so there is a full month of
retries before anything is at risk. Waiting until the final week means a transient DNS problem
becomes an outage.

Only certificates whose recorded source is **ACME** are renewed. That sounds obvious and was a
real defect: issuance originally stored its result through the operator-import path, which
records `ImportedPfx` — a source the aggregate correctly refuses to auto-renew, because this
server cannot reissue someone else's imported certificate. The effect was that every certificate
obtained automatically would have expired without one renewal attempt, while the renewal loop
ran happily and found nothing to do. A test now asserts both the source and the loop's own
filter condition.

A failed renewal leaves the existing certificate and its binding exactly as they were. There is
no code path from a renewal failure to a self-signed substitute, and
`CertificateRenewalPolicy.MayDowngradeToSelfSignedOnRenewalFailure` exists as a permanently
false constant so a test can say so.

## Account key protection

The ACME account key is ES256, held in the DPAPI-protected secret store, and never written to a
log — rule 77 lists ACME private keys among the things that must never reach one.

**Losing it means losing the ability to revoke** certificates issued through that account, which
is precisely the ability most needed after a key compromise. Two consequences follow:

* The key is **stored, never regenerated on a miss**. A missing key is reported as an error for
  an operator to resolve, not quietly replaced with a new one — that would orphan every
  certificate the old account issued.
* Deactivating an account **keeps** its row and its key. Nothing here deletes one.

Staging and production hold **separate accounts with separate keys**, under separate secret
names. One shared name would mean registering against production destroyed the staging key and
with it the ability to revoke anything staging had issued.

The key is included in the secrets re-wrapped at backup time — see `docs/BackupRestore.md`.

---

## Wildcards

Not supported yet, and refused with a message that says why rather than a generic validation
error.

A wildcard can be *obtained* — it needs DNS-01, which this server does — but it could not then
be *presented*: the TLS layer selects a certificate by exact SNI hostname, so a certificate
bound to `*.example.com` would never be chosen for any name it covers. Issuing one would spend
real quota on something the server cannot serve.

List the hostnames explicitly instead. Wildcard support needs wildcard-aware binding lookup in
`TlsCertificateProvider`, which is a change to the handshake path rather than to ACME.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Validation fails on HTTP-01 | Port 80 blocked upstream, or DNS not pointing here yet. Verify from **outside** your network |
| Validation fails on DNS-01 | Record not yet propagated. Check the **authoritative** servers, not your local resolver |
| "too many certificates already issued" | Rate limit. Wait; do not retry. Use staging for further testing |
| "too many failed authorizations" | 5 per hour per hostname. Fix the underlying problem before retrying |
| Certificate issued but clients still warn | The binding was not updated, or the SAN does not cover the name the client used |
