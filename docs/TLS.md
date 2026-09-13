# TLS

> **Status: Planned — Milestones 3, 6, 7, 10 and 11.**

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

There is no `RemoteCertificateValidationCallback` returning `true` anywhere in the product, and
no `TrustServerCertificate` shortcut on the database link. A security test asserts this.

Where outbound SMTP encounters an untrusted certificate, the result is recorded in the delivery
attempt — with the peer's subject and issuer — so a genuine problem is diagnosable rather than
invisible.

## Session recording

TLS version, cipher suite and peer certificate details are recorded per delivery attempt. When
a receiver later asks why mail was refused, or a TLS-RPT report shows failures, that record is
what turns the question into an answer.
