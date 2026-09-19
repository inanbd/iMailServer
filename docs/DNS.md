# DNS Architecture

> **Status: `IDnsResolver` implemented in Milestone 8. `IDnsDiagnosticsService` implemented in Milestone 11.**

## Two consumers, two abstractions

`IDnsResolver` is the hot path: MX resolution for delivery. Cached, bounded, fast. Implemented
in Milestone 8 as `DnsMxResolver` (`src/MailServer.Infrastructure/Dns/`), on `DnsClient.NET`;
see `DnsMxResolverTests` for the classification matrix this page describes.

`IDnsDiagnosticsService` is for the admin tools. It **bypasses the cache** and may query
authoritative nameservers directly, because "it works on my resolver" is exactly the problem a
diagnostic tool exists to solve. It reports the TTL, the answering server, and the actual
versus expected value.

It is backed by its own `LookupClient` rather than a flag on the shared one, because the two
want opposite things — and an operator who has just corrected a record and is asking whether the
correction took would otherwise be told about the old one. Failed results are not cached either,
for the same reason. The TTL it reports is the **smallest** in the answer, since that is the one
that decides how long a correction takes to become visible.

**An empty answer is a success, not a failure.** A name that exists and has no TXT record is a
fact about the configuration, and only the caller knows whether the absence matters. Reporting it
as a lookup failure would make every "you have not published this yet" finding indistinguishable
from a resolver outage — which is the one distinction the whole readiness score depends on.

`DnsClient.NET` underpins both. `Dns.GetHostEntry` cannot do MX, TXT or PTR at all.

## Failure semantics

The most consequential detail in the whole DNS layer:

| Result | Classification | Consequence |
|---|---|---|
| `SERVFAIL`, timeout | **Temporary** | 4xx, retry later |
| `NXDOMAIN` | **Permanent** | 5xx, bounce now |

Conflating these causes either lost mail (bouncing on a transient failure) or infinite retries
(retrying a domain that does not exist).

## MX selection

* Group by priority; **shuffle within a priority band** (RFC 5321 §5.1) so load spreads.
* Try bands in order, remembering per-host failures for the retry window.
* **Implicit MX:** a domain with no MX but an A/AAAA record falls back to that host.
* **Null MX** (`0 .`) is honoured as "this domain accepts no mail" — an immediate permanent
  failure, not a retry loop.

## Caching

TTLs are respected, with a floor of 30 seconds and a ceiling of one hour. Negative caching uses
a shorter TTL. Without a floor, a domain publishing 0-second TTLs would have us re-querying on
every message.

## DNSSEC and DANE

Not validated in v1. `IDnsResolver` exposes an authenticated-data flag so DANE can be enabled
later **only when validation is genuinely available**.

Claiming DANE support without DNSSEC validation would be actively harmful: it would present a
security guarantee the server cannot actually make. See `docs/Standards.md`.

## Records a domain needs

For `example.com` with mail host `mail.example.com` at `203.0.113.10`:

```text
mail            A       203.0.113.10
@               MX      10 mail.example.com
@               TXT     v=spf1 mx ip4:203.0.113.10 -all
mail2026._domainkey  TXT  v=DKIM1; k=rsa; p=<public key>
_dmarc          TXT     v=DMARC1; p=none; rua=mailto:dmarc@example.com
_mta-sts        TXT     v=STSv1; id=<version>
_smtp._tls      TXT     v=TLSRPTv1; rua=mailto:tlsrpt@example.com
```

Plus, configured **by the IP owner** — your hosting provider, datacentre or ISP, never in your
own zone:

```text
203.0.113.10    PTR     mail.example.com
```

## PTR and FCrDNS

Forward-Confirmed reverse DNS means the PTR for your sending IP resolves to a name, and that
name resolves back to the same IP.

**Major receivers reject or spam-folder mail from IPs without correct FCrDNS.** It is not
optional, it cannot be fixed in your own DNS zone, and it is the single most common reason a
self-hosted server cannot deliver to Gmail. If your provider will not set a PTR record, you
cannot run a public mail server on that IP — no amount of correct SPF, DKIM or DMARC
compensates.

The EHLO name, the PTR record, the TLS certificate SAN and the MX target must all agree. That
is why `MailServer:Server:Hostname` is validated as a real FQDN at startup and the service
refuses to start otherwise.
