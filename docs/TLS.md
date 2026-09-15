# TLS

> **Status: certificate handling and validation are built (Milestone 3). The listeners that
> use them arrive in Milestones 6, 7 and 10; outbound TLS policy in Milestone 8; MTA-STS and
> TLS-RPT in Milestone 11.**

## Where TLS applies

| Endpoint | Port | Mode |
|---|---|---|
| SMTP inbound | 25 | STARTTLS, opportunistic |
| SMTP submission | 587 | STARTTLS, **required before AUTH** |
| SMTP implicit | 465 | Implicit from byte zero |
| IMAP | 993 | Implicit |
| POP3 (opt-in) | 995 | Implicit |
| HTTPS | 443 | Implicit |

## Opportunistic on 25, mandatory on submission

Port 25 offers STARTTLS but **cannot require it**. A large number of legitimate MTAs still do
not support it, and refusing them would silently lose mail. This is the pragmatic reality of
inter-server SMTP, and it is why MTA-STS and DANE exist as separate opt-in mechanisms.

Submission is different: it carries credentials. AUTH is never offered before TLS on 587, and
465 is encrypted from the first byte. Rule 105's "No plaintext SMTP AUTH over Internet" is
enforced by never advertising the capability, not merely by rejecting the attempt.

## Minimum version

TLS 1.2 by default; 1.3 preferred where both ends support it. TLS 1.0 and 1.1 are not offered.

Cipher selection is left to the OS policy rather than hardcoded. Windows Server's SCHANNEL
policy is centrally manageable and gets updated as attacks evolve; a hardcoded list in an
application ossifies the day it ships.

## Outbound TLS policy

> **Status: Opportunistic and required modes implemented in Milestone 8**
> (`OutboundSmtpClient`, `src/MailServer.Infrastructure/Smtp/Outbound/`). MTA-STS enforcement and
> REQUIRETLS remain planned for Milestone 11; the table below states the target policy, not a
> claim that every row is built.

| Setting | Behaviour |
|---|---|
| Opportunistic (default) | Use TLS when the remote offers it; deliver in plaintext otherwise |
| Required per domain | `RequireTlsForOutbound` — **fail** rather than deliver in plaintext |
| MTA-STS enforce | Honour the remote's published policy |
| REQUIRETLS | Honour a per-message requirement |

A security policy that downgrades itself when inconvenient is not a security policy. When TLS
is required and cannot be established, delivery **fails** and is reported — it does not quietly
fall back.

## Certificate validation

There is no `RemoteCertificateValidationCallback` returning `true` anywhere in the product, no
`TrustServerCertificate = true`, and no `RevocationMode.NoCheck`.

`NoCertificateValidationBypassTests` scans every production source file for each of those
constructs and fails the build on any of them. The scan itself was verified by introducing a
bypass deliberately and confirming it failed — a security test that cannot fail is worse than
no test, because it reports safety it never checked.

One subtlety the scan encodes: `TrustServerCertificate` is *read* in `SqlServerConnectionFactory`
so that an operator who put it in their own connection string gets a warning naming the exposure
it creates. Reading it to warn is correct; setting it is the bypass, so the scan matches the
assignment rather than the mention. Silently clearing an operator's setting would be the wrong
answer to a different problem — their server would simply stop connecting, with no indication
why.

Inbound chain validation uses `X509Chain` with `RevocationMode.Online`,
`RevocationFlag.ExcludeRoot` and `VerificationFlags.NoFlag`. An *unreachable* revocation
responder is treated as trusted-with-a-warning: it is a network fault, not evidence against the
certificate, and treating it as untrusted would turn a CA's OCSP outage into every certificate
here suddenly becoming invalid.

Where outbound SMTP encounters an untrusted certificate, the result is recorded in the delivery
attempt — with the peer's subject and issuer — so a genuine problem is diagnosable rather than
invisible.

## Session recording

TLS version, cipher suite and peer certificate details are recorded per delivery attempt. When
a receiver later asks why mail was refused, or a TLS-RPT report shows failures, that record is
what turns the question into an answer.
