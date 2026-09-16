# DMARC

> **Status: Partial — Milestone 9.** Policy discovery (exact domain, falling back once to the
> organizational domain per §6.6.3), alignment, `pct=` sampling and `p=reject` enforcement at the
> SMTP level are built and tested, including against RFC 7489 Appendix B.1's official alignment
> examples and a real embedded Public Suffix List snapshot. **Aggregate and failure reporting
> (`rua=`/`ruf=`) are not implemented** — see "Aggregate reports" below — and ARC is groundwork
> only: structural parsing, no cryptographic chain validation. See `docs/Architecture.md`'s A9
> addendum for the full list of what this milestone did and did not build.

DMARC (RFC 7489) ties SPF and DKIM to the `From:` header the user actually sees, and tells
receivers what to do when neither aligns.

## Alignment is the whole point

A message passes DMARC if **at least one** of these holds:

* **SPF alignment** — SPF passed *and* the `MAIL FROM` domain aligns with the `From` domain.
* **DKIM alignment** — a DKIM signature verified *and* its `d=` domain aligns with the `From`
  domain.

Alignment modes:

| Mode | `From: user@mail.example.com` matches |
|---|---|
| `relaxed` (default) | `example.com` — same organisational domain |
| `strict` | `mail.example.com` only |

A passing SPF check for an unrelated domain does **not** produce a DMARC pass. That is
precisely the gap DMARC exists to close.

## Deployment path

Never start at `reject`.

```text
p=none       → collect reports, find every legitimate sender, fix what fails
p=quarantine → failures go to spam; watch the reports for a few weeks
p=reject     → failures are refused outright
```

```text
_dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
```

Publishing `p=reject` before legitimate senders are verified **causes your own mail to be
rejected**, and the reports that would have told you which senders were missing arrive after
the damage — except this product does not yet generate those reports at all (see "Aggregate
reports" above), so today that feedback loop does not exist regardless of policy. **There is no
admin UI for DMARC policy** to recommend anything through; a domain's policy is whatever its own
DNS `_dmarc` TXT record says, published and edited entirely outside this product.

Only `p=reject`'s disposition is actually enforced by this server, as an SMTP-level refusal
after `pct=` sampling (`LocalDeliveryService`/`SmtpConnectionHandler`). `p=quarantine` is
evaluated and recorded (`DmarcVerificationRecord.Disposition`) exactly like `p=reject` is, but
nothing moves the message into a separate spam/quarantine location — it is delivered normally.
Recording without enforcing is a deliberate, minimal first step; routing quarantined mail
somewhere different is unbuilt work, not a design decision that quarantine means nothing here.

## Organisational domain and the Public Suffix List

Relaxed alignment compares *organisational* domains, which requires the Public Suffix List.

Without it, `example.co.uk` and `other.co.uk` appear to share the organisational domain
`co.uk` and would wrongly align. A stale PSL produces subtly wrong alignment results in both
directions, so **the list ships with the product** (a real snapshot fetched from
publicsuffix.org, embedded at build time — not a heuristic) **and its age is a health check**:
`PublicSuffixListLoader` logs a warning once the embedded snapshot's own recorded date passes
180 days. **Refreshing it is not automated.** There is no live fetch and no scheduled
housekeeping job yet — updating the snapshot means replacing
`src/MailServer.Infrastructure/Dmarc/public_suffix_list.dat` from publicsuffix.org and shipping
a new build, an operational task today rather than something this server does on its own.

## Aggregate reports — not implemented

Receivers would send XML reports to the `rua=` address, and an analyser would present:

| Column | Use |
|---|---|
| Reporter | Which receiver |
| Source IP | Who sent as your domain |
| Count | Volume |
| SPF / DKIM result | What passed |
| Alignment | Whether it counted |
| Disposition | What the receiver did |

The **Unknown Sources** figure would be the one to watch during rollout: the list of things
sending as your domain that has not yet been accounted for — some legitimate and forgotten,
some not yours at all. None of this — report ingestion, the analyser, or this figure — exists
yet; `DmarcVerificationRecord` records this server's own per-message verdict for its own
mailboxes' inbound mail, which is a different thing from receiving reports about how *other*
receivers treated mail claiming to be from *this server's* domains.

## Forwarding, ARC and SRS

Forwarding breaks SPF and, if the message is re-encoded, DKIM as well. Three mitigations, of
which only the first is something this server can simply do correctly rather than build:

* **Preserve the DKIM signature bit-for-bit.** Re-encoding a forwarded message is the most
  common way self-hosted servers break DMARC for their users. This server's outbound path does
  not re-encode a message it did not originate.
* **SRS is not implemented.** Rewriting the envelope sender to a locally-signed, time-limited,
  HMAC-authenticated address so a forwarding hop passes SPF is real, useful work this milestone
  did not do — see `docs/Standards.md`'s SRS row.
* **ARC (RFC 8617) is groundwork only.** `ArcChain.Parse` structurally parses and groups a
  message's `ARC-Seal`/`ARC-Message-Signature`/`ARC-Authentication-Results` headers by instance
  number and checks well-formedness (contiguous instances, a correctly placed `cv=none`), purely
  as observation. **No cryptographic seal or signature is verified**, and nothing in this
  product currently lets a validated ARC chain rescue a forwarded message that fails DMARC on
  its own — building that trust is future work this groundwork prepares for, not something it
  does. A security test (`NoUntrustedAuthenticationHeaderTrustTests`) asserts that no
  SPF/DKIM/DMARC decision anywhere reads an ARC header's claims as its own verdict.

Naïve forwarding that damages DMARC deliverability for your own users is a bug, not a
limitation.

## Inbound handling

Results are composed into a **local** `Authentication-Results` header value stamped with our
own `authserv-id` (`AuthenticationResultsComposer`), built only from this server's own SPF
outcome, its own DKIM verification, and its own DMARC verdict — never from a header already on
the wire. **This composed value is not yet attached to a served message**: the first real
consumer, IMAP `FETCH`, is a later milestone, so today it exists as a tested formatter with
nowhere to write to yet. When that consumer exists, any pre-existing `Authentication-Results`
header from an untrusted upstream must be stripped or renamed at the point of serving — the
stored original is never mutated (the same discipline `DkimVerificationRecord` and
`DmarcVerificationRecord` already follow) — rather than left for a client to confuse with this
server's own verdict.

Trusting an attacker-supplied `Authentication-Results: dmarc=pass` header is a complete
authentication bypass, and it is trivially easy to do by accident. A security test
(`NoUntrustedAuthenticationHeaderTrustTests`) scans every production source file to assert that
no SPF/DKIM/DMARC decision anywhere reads an incoming `Authentication-Results` or `ARC-*` header
as a trust input.
