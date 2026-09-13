# Let's Encrypt and ACME

> **Status: Planned — Milestone 4.**

Automatic, free, publicly trusted certificates via ACME v2 (RFC 8555), using the **Certes**
library. Hand-implementing ACME's JWS signing, nonce handling and key-authorisation digests
would be an unnecessary cryptographic risk.

## Requirements before you start

| For HTTP-01 | For DNS-01 |
|---|---|
| Public DNS A/AAAA pointing at this server | Control of the domain's DNS |
| **Inbound TCP 80 reachable** | An API-capable DNS provider, or willingness to do it by hand |
| | Required for wildcards |

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
`IDnsChallengeProvider` and then polled at the **authoritative** nameservers until it
propagates. Checking a recursive resolver would report success before the CA can see it.

No DNS provider is hardcoded into the architecture. Cloudflare, Route 53, Azure DNS,
DigitalOcean, GoDaddy, Namecheap and a generic webhook are all provider modules behind the same
interface.

**Manual DNS-01** is a first-class fallback for operators with no supported API: the UI shows
the exact record to create, offers a **Check DNS** button that queries the authoritative
servers, and only then continues.

## Rate limits — read this before troubleshooting

Let's Encrypt production limits that matter:

| Limit | Value |
|---|---|
| Certificates per registered domain | 50 per week |
| Duplicate certificates | 5 per week |
| Failed validations | 5 per account, per hostname, per hour |

**New installations default to the staging directory for a trial issuance**, then switch to
production. This is not caution for its own sake: an operator fixing DNS while retrying
against production can exhaust the duplicate-certificate limit in an afternoon and then wait a
week.

The client additionally tracks recent attempts locally and **refuses** to submit an order that
would obviously breach a documented limit, explaining why. Hammering the CA gets an
installation blocked.

Staging certificates are **not publicly trusted**. That is the point — they prove the flow
works without spending production quota.

## Renewal

`CertificateLifecycleHostedService` checks every 12 hours.

```text
≤ 30 days remaining  → attempt renewal
≤ 21 / 14 / 7 days   → escalate health severity at each threshold
failure              → keep the existing certificate, back off, alert
                       NEVER downgrade to self-signed
```

Thirty days is deliberate: Let's Encrypt certificates last 90, so there is a full month of
retries before anything is at risk. Waiting until the final week means a transient DNS problem
becomes an outage.

## Account key protection

The ACME account key is DPAPI-protected and never written to a log. Losing it means losing
the ability to revoke previously issued certificates through that account.

It is included in the secrets re-wrapped at backup time — see `docs/BackupRestore.md`.

## Troubleshooting

| Symptom | Cause |
|---|---|
| Validation fails on HTTP-01 | Port 80 blocked upstream, or DNS not pointing here yet. Verify from **outside** your network |
| Validation fails on DNS-01 | Record not yet propagated. Check the **authoritative** servers, not your local resolver |
| "too many certificates already issued" | Rate limit. Wait; do not retry. Use staging for further testing |
| "too many failed authorizations" | 5 per hour per hostname. Fix the underlying problem before retrying |
| Certificate issued but clients still warn | The binding was not updated, or the SAN does not cover the name the client used |
