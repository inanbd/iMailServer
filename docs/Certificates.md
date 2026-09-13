# Certificates

> **Status: Planned — Milestone 3 (infrastructure) and Milestone 4 (ACME).**

TLS certificates are a major subsystem, not a configuration detail. Four sources, one
hot-swappable provider, and one policy that is never violated.

## Sources

| Source | Use |
|---|---|
| **Let's Encrypt (ACME)** | Recommended for any Internet-facing production server |
| **Self-signed** | Development, isolated networks, initial bootstrap |
| **Imported PFX** | An existing certificate from another CA |
| **Windows Certificate Store** | Production certificates managed by existing tooling |

## Bindings

A `CertificateBinding` maps a hostname and purpose to a certificate. One certificate typically
covers SMTP, IMAP and HTTPS via SAN entries; separate bindings are supported where an operator
wants them.

## Hot reload without a restart

Listeners never capture an `X509Certificate2` at startup. They pass a
`ServerCertificateSelectionCallback` to `SslStream`, which asks `TlsCertificateProvider` on
**every handshake**.

Renewal therefore becomes a single atomic reference swap: new connections use the new
certificate, in-flight sessions finish on the old one, and nothing restarts. The previous
certificate is retained for a rollback window.

Restarting SMTP and IMAP listeners to pick up a renewed certificate would drop live sessions
every 60 days, which is precisely the kind of avoidable disruption that erodes confidence in
automation.

## Self-signed generation

Generated with `CertificateRequest` and `RSA` from the BCL — no external dependency.

| Property | Value |
|---|---|
| Key | RSA 3072 by default (2048 and 4096 offered) |
| Signature | SHA-256 |
| EKU | Server Authentication only |
| Basic constraints | `CA=false`, critical |
| Key usage | `DigitalSignature \| KeyEncipherment`, critical |
| SAN | Every configured hostname — CN alone is ignored by modern clients |
| Validity | 1 / 2 / 5 years, default 1 |

Every surface showing a self-signed certificate displays this verbatim:

```text
SELF-SIGNED CERTIFICATES ARE NOT PUBLICLY TRUSTED.
MAIL CLIENTS AND REMOTE SYSTEMS MAY DISPLAY CERTIFICATE WARNINGS.
USE LET'S ENCRYPT OR ANOTHER PUBLIC CA FOR INTERNET-FACING PRODUCTION SERVERS.
```

The deliverability score deducts the full certificate-trust weighting for a self-signed
certificate on an Internet-facing server, so the cost is a number rather than only a banner.

## Windows Certificate Store

Certificates may live in `LocalMachine\My`, referenced by thumbprint.

Private keys are **not** exported to disk when the store holds them. The service account is
granted read access to the key container through the CNG/CAPI key security descriptor — the
narrowest grant that works — applied by the installer.

Chain validation uses `X509Chain` with explicit policy: revocation checked online with offline
fallback. There is **no** `RemoteCertificateValidationCallback` returning `true` anywhere in
the product, and a security test asserts it.

## The fallback policy — never violated

```text
Renewal fails while the current certificate is still valid
    → KEEP the current certificate
    → log Critical, raise a health alert, notify the administrator
    → retry with backoff
    → NEVER substitute a self-signed certificate
```

Silently downgrading a publicly trusted certificate to self-signed would turn a renewal warning
into a fleet-wide TLS failure with every remote MTA and every mail client simultaneously. A
self-signed certificate is used only where one was explicitly chosen, or at first bootstrap
when no certificate exists at all.

As expiry approaches, health escalates at 30, 21, 14 and 7 days. Certificate renewal health is
part of the deliverability score, so a stalled renewal is visible on the dashboard rather than
only in a log nobody is reading.

## What the UI shows

Hostname · Source · Issuer · Subject · SAN · Thumbprint · Serial · Valid from · Valid until ·
Days remaining · Auto-renew · Last renewal · Next renewal · Status.

Status uses the same four-state vocabulary as everything else, plus the specific failure
modes: `Healthy`, `Renewing`, `Expiring Soon`, `Expired`, `Invalid`, `Hostname Mismatch`,
`Untrusted`.

## Backup considerations

Certificate private keys and their passphrases are DPAPI-protected and therefore **machine
scoped**. A backup restored onto a new machine cannot decrypt them.

Backups re-wrap them under a passphrase-derived key at export time. This is an exercised
procedure, not a discovery made during a disaster — see `docs/BackupRestore.md`.
