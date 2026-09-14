# Certificates

> **Status: Milestone 3 complete (infrastructure). ACME is Milestone 4.**
>
> Built and tested: self-signed generation, PKCS#12 import, Windows-store adoption, hostname
> bindings, hot reload without restart, expiry monitoring and health. Not yet built: automatic
> renewal, which needs a certificate authority to renew *with* — see
> [Renewal](#renewal-milestone-4) below for what Milestone 3 deliberately does not do.

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

A `CertificateBinding` maps a hostname and a set of purposes to a certificate. One certificate
typically covers SMTP, IMAP and HTTPS via SAN entries; separate bindings per purpose are
supported where an operator wants them.

A binding **outlives** the certificates it points at. A certificate is replaced every 60–90
days; the statement "mail.example.com is served by whatever currently covers it" does not
change. Renewal therefore repoints one row instead of rewriting configuration, which is what
makes hot reload a reference swap rather than a reconfiguration.

Two invariants are held by the database, not by code paths that could forget them:

* **One binding per hostname** — a unique index. Two would make the certificate presented depend
  on row order, and a TLS configuration that varies between restarts is not diagnosable.
* **At most one default** — a unique *filtered* index (`WHERE IsDefault = 1`). This one has a
  consequence for write ordering: the old default must be cleared **before** the new row claims
  the flag, or the constraint rejects the write. Getting that backwards is a bug that only
  appears when a *second* certificate is made the default, never the first; a test caught it.

## Binding refuses a certificate that does not cover the hostname

`Certificates.Bind` fails if the certificate's subjectAltName list does not match the hostname,
and the error names the SANs it does carry.

The alternative — accepting it with a warning — moves the failure from one clear message here to
a warning dialog in every connecting client, discovered through user reports.

Coverage follows RFC 6125 §6.4.3 strictly. `*.example.com` matches `mail.example.com` but **not**
`example.com` and **not** `a.b.example.com`; a partial-label wildcard such as `m*.example.com` is
refused outright rather than accepted and quietly not matched. Erring permissive is the harmful
direction: it makes the server report a hostname as covered while clients reject it.

The common name is never consulted for coverage. RFC 6125 deprecated CN-based matching and
current clients ignore it, so a certificate whose hostname appears only in the CN covers nothing
— treating it as covered would mean reporting Healthy while clients showed warnings.

## Hot reload without a restart

Listeners never capture an `X509Certificate2` at startup. They pass a
`ServerCertificateSelectionCallback` to `SslStream`, which calls
`ITlsCertificateProvider.Select(hostname, purpose)` on **every handshake**.

`TlsCertificateProvider` is a singleton holding one immutable snapshot in a field replaced by
`Interlocked.Exchange`. Readers take no lock: they read the reference once and use whatever
they got. Writers build a complete new snapshot off the handshake path and publish it in a
single instruction.

**Why a whole snapshot rather than a concurrent dictionary.** A reload changes several entries
at once — a renewed certificate, its binding, possibly the default. A mutable map would expose
intermediate states in which a handshake could see the new certificate for one hostname and the
old one for another, or briefly find no default at all. Swapping a whole snapshot means no
handshake ever observes a half-applied reload.

**The rollback window.** The previous snapshot's certificates are not disposed immediately. A
handshake that read the old reference microseconds before the swap is still using them, and
disposing an `X509Certificate2` out from under an in-flight handshake throws
`ObjectDisposedException` inside the TLS stack — an intermittent TLS failure with no obvious
cause. They are held for five minutes and disposed on the next reload after that. A test holds
a certificate across a reload and asserts it is still usable.

**When the reload happens.** A handler that changes a binding cannot reload the provider itself:
it runs inside the request's transaction, so the rows it just wrote are not visible on the fresh
connection the provider uses. It would rebuild from the state *before* the change and log
success — a hot swap that silently does not swap, which is worse than one that fails loudly.

Handlers therefore signal `ITlsReloadCoordinator.RequestReload()`, and `TlsReloadBehavior` —
registered immediately outside `TransactionBehavior` — performs the reload once the transaction
has committed. A rolled-back request reloads nothing, because there is no committed change to
pick up. `PipelineOrderTests` asserts the ordering.

Restarting SMTP and IMAP listeners to pick up a renewed certificate would drop live sessions
every 60 days: interrupted deliveries and disconnected IMAP clients on a schedule, which is
exactly the kind of self-inflicted disruption that teaches operators to turn automation off.

---

## Selection rules

| Client sends | Server presents |
|---|---|
| An SNI hostname with a binding covering this service | That binding's certificate |
| An SNI hostname with a binding **not** covering this service | The default |
| An unknown SNI hostname | The default |
| **No SNI at all** | The default |

The last row is not an edge case. SNI is a TLS extension, older MTAs still connect without it,
and inbound mail from them is exactly the traffic a mail server cannot afford to drop. A
deployment with no default binding fails those handshakes, and the failure is reported by the
*sender*, not by this server — which is why it gets its own health warning and its own banner in
the admin UI rather than being left to be discovered.

Matching is case-insensitive, because DNS names are.

An unknown hostname falls back to the default rather than refusing: a name mismatch is a warning
the remote can choose to accept, whereas no certificate is a hard handshake failure. The lesser
harm is the right default.

---

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

The warning lives as a single constant, `CertificateRenewalPolicy.SelfSignedWarning`, and the
UI binds to it rather than restating it. "Verbatim" is only meaningful if there is exactly one
copy; three hand-typed variants across three views is how a warning quietly softens into a hint.

The deliverability score deducts the full certificate-trust weighting for a self-signed
certificate on an Internet-facing server (Milestone 11), so the cost becomes a number rather
than only a banner.

**Where the key goes.** A generated certificate is always written as a DPAPI-protected PKCS#12
file, even on Windows. Writing into `LocalMachine\My` needs elevation the service does not hold
at runtime, and installing into the machine store is deliberately an installer-time, audited
operation rather than something a background process does on its own.

**Two layers of protection.** The PKCS#12 is encrypted under a randomly generated 256-bit
passphrase, and that passphrase is held in the DPAPI-protected secret store. Someone who copies
the file gets ciphertext; someone who copies the database gets the passphrase only as DPAPI
ciphertext bound to the original machine. Neither alone is sufficient. A test reads the file off
disk and asserts it cannot be opened without the passphrase.

The passphrase never appears in `CertificateKeyLocation`, which carries only the secret's
*name* — which is what lets certificate metadata be logged, audited, sent over IPC and rendered
in the admin UI without any of those paths touching a private key.

**Bootstrap generation.** On first start, a server with *no* certificate at all generates one
for its configured hostname so that TLS is available enough to configure a real one. The guard
is "no certificates exist", not "no valid certificate exists" — an expired certificate must not
trigger generation, because that would be the downgrade the fallback policy forbids arriving
through the back door of a bootstrap check.

## Windows Certificate Store

Certificates may live in `LocalMachine\My`, referenced by thumbprint.

Private keys are **not** exported to disk when the store holds them. The service account is
granted read access to the key container through the CNG/CAPI key security descriptor — the
narrowest grant that works — applied by the installer.

The store is opened `ReadOnly` and **nothing in this product writes to or deletes from it**.
Adoption is not ownership: a certificate in `LocalMachine\My` may belong to IIS or to a
line-of-business application, and removing our database row is not consent to delete something
we did not install. Deleting an adopted certificate here removes only this server's reference to
it.

Chain validation uses `X509Chain` with explicit policy: `RevocationMode.Online`,
`RevocationFlag.ExcludeRoot`, `VerificationFlags.NoFlag`.

A revocation responder being *unreachable* is treated as trusted-with-a-warning rather than
untrusted. It is a network fault, not evidence against the certificate, and treating it
otherwise would turn a CA's OCSP outage into every certificate here suddenly becoming invalid.

There is **no** `RemoteCertificateValidationCallback` returning `true`, no
`TrustServerCertificate = true`, and no `RevocationMode.NoCheck` anywhere in the product.
`NoCertificateValidationBypassTests` scans every production source file for each of those
constructs and fails the build on any of them. The scan is itself verified: a deliberately
introduced bypass was confirmed to fail it, because a security test that cannot fail is worse
than none.

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

The rule exists as an assertable property — `CertificateRenewalPolicy.MayDowngradeToSelfSigned\
OnRenewalFailure`, permanently false — rather than as an absence, so a test can state it and a
future contributor has to argue with a named constant rather than silently add a fallback.

There is deliberately no method on the `Certificate` aggregate that replaces a failed
certificate with a self-signed one. `FailRenewal` records the reason and leaves everything else
untouched; a test asserts the thumbprint, expiry and source are unchanged afterwards.

### Escalation

Health escalates at **30, 21, 14 and 7 days**, and the *lowest* crossed threshold is reported —
so an alert at 20 days says "21" and one at 6 says "7". Reporting the highest would make every
alert from 30 days onward read "30", and the escalation an operator is supposed to notice would
be invisible.

Four steps rather than one, because a single notice at 30 days is read once and forgotten, and a
single notice at one day arrives too late to act on.

| Days remaining | Health | Log level |
|---|---|---|
| > 30 | Healthy | — |
| 30 – 8 | Warning | Warning, at each threshold crossing |
| 7 – 1 | Critical | Critical |
| Expired | Critical | Critical |

A self-signed certificate raises a Warning on its own account regardless of expiry, and a
missing default binding escalates above that — its consequence is dropped mail rather than a
client warning dialog.

---

## Renewal

Automatic renewal arrived in Milestone 4 and is documented in
[LetsEncrypt.md](LetsEncrypt.md#renewal). It uses the escalation thresholds above.

Only certificates whose source is **ACME** are renewed. The `Certificate` aggregate refuses
`AutoRenew` for every source this server cannot reissue — imported PFX, Windows store,
self-signed — and that refusal is a throw, not a default: a switch that can be turned on and
silently does nothing while the certificate expires is worse than no switch.

That rule has a sharp edge worth knowing about, because it drew blood. Issuance originally
stored ACME certificates through the operator-import path, which records `ImportedPfx` — so the
refusal applied to them too, and nothing ever renewed. See
[A4.2](Architecture.md#a42--the-source-a-certificate-is-stored-under-decides-whether-it-renews).

## What the UI shows

Hostname · Source · Issuer · Subject · SAN · Thumbprint · Serial · Valid from · Valid until ·
Days remaining · Auto-renew · Last renewal · Status · Bindings.

`CertificateDto` carries metadata only — no file path, no secret name, no key material — which
is what makes the certificate page safe to screenshot, safe to log on error, and safe to include
in a support bundle. A test serialises the DTO and asserts none of those appear in it.

Status is derived server-side from the certificate, the clock and the hostnames it is bound to,
so a dashboard and a detail page cannot disagree:

`Healthy` · `Renewing` · `ExpiringSoon` · `Expired` · `Invalid` · `HostnameMismatch` ·
`Untrusted`.

Derivation runs **worst-first**. An expired certificate that also fails to cover its hostname
reports `Expired`, because that is the fault to fix; reporting the name mismatch would send an
operator to reissue with different SANs and discover the expiry afterwards.

A self-signed certificate reports `Untrusted` rather than `Healthy`. Its chain never builds to a
trusted root, and saying so is more useful than a green tick on something every client will warn
about.

## Backup considerations

Certificate private keys and their passphrases are DPAPI-protected and therefore **machine
scoped**. A backup restored onto a new machine cannot decrypt them.

Backups re-wrap them under a passphrase-derived key at export time. This is an exercised
procedure, not a discovery made during a disaster — see `docs/BackupRestore.md`.
