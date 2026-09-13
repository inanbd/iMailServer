# DMARC

> **Status: Planned — Milestone 9.**

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
the damage. The admin UI will not recommend `reject` until aggregate reports show a clean
period, and the documentation says so wherever the policy is editable.

## Organisational domain and the Public Suffix List

Relaxed alignment compares *organisational* domains, which requires the Public Suffix List.

Without it, `example.co.uk` and `other.co.uk` appear to share the organisational domain
`co.uk` and would wrongly align. A stale PSL produces subtly wrong alignment results in both
directions, so the list ships with the product, is refreshed by housekeeping, and **its age is
a health check** rather than an assumption.

## Aggregate reports

Receivers send XML reports to the `rua=` address. The analyser presents:

| Column | Use |
|---|---|
| Reporter | Which receiver |
| Source IP | Who sent as your domain |
| Count | Volume |
| SPF / DKIM result | What passed |
| Alignment | Whether it counted |
| Disposition | What the receiver did |

The **Unknown Sources** figure is the one to watch during rollout: it is the list of things
sending as your domain that you have not yet accounted for — some legitimate and forgotten,
some not yours at all.

## Forwarding, ARC and SRS

Forwarding breaks SPF and, if the message is re-encoded, DKIM as well. Three mitigations:

* **Preserve the DKIM signature bit-for-bit.** Re-encoding a forwarded message is the most
  common way self-hosted servers break DMARC for their users.
* **SRS** rewrites the envelope sender to a locally-signed, time-limited, HMAC-authenticated
  address so the forwarding hop passes SPF. The `From:` header is untouched, so DKIM alignment
  is unaffected.
* **ARC** (RFC 8617) lets a forwarder attest that the message passed authentication when it
  arrived, so a downstream receiver can rescue legitimate forwarded mail.

Naïve forwarding that damages DMARC deliverability for your own users is a bug, not a
limitation.

## Inbound handling

Results are written into a **local** `Authentication-Results` header stamped with our own
`authserv-id`. Pre-existing `Authentication-Results` headers from untrusted upstreams are
stripped or renamed first.

Trusting an attacker-supplied `Authentication-Results: dmarc=pass` header is a complete
authentication bypass, and it is trivially easy to do by accident.
