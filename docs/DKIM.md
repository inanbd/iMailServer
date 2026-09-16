# DKIM

> **Status: Partial — Milestone 9.** Signing, verification and DNS key lookup are built and
> tested, including against RFC 6376's official canonicalization vectors — see
> `docs/Standards.md` for the exact scope. **The real gap:** there is no operator-facing command
> yet to generate a key and activate it for a domain — see "What is not built yet" below. None of
> this depends on MimeKit; see `docs/Architecture.md`'s A9 addendum for why.

DomainKeys Identified Mail (RFC 6376) signs outbound mail so receivers can verify it was
authorised by the domain owner and has not been altered in transit.

## Signing

Default: **RSA-2048, SHA-256, relaxed/relaxed canonicalisation.**

The signed header set is curated and stable: `From`, `To`, `Cc`, `Subject`, `Date`,
`Message-ID`, `MIME-Version`, `Content-Type` and the content-transfer headers.

**`From` is always signed and oversigned** — listed twice in `h=`. Oversigning means a relay
cannot *add* a second `From` header without breaking the signature, which blocks a header-
injection replay attack.

**`l=` (body length) is omitted by default.** It tells verifiers to check only the first *n*
bytes, which enables a content-append attack: an attacker forwards your legitimately signed
message with extra content appended, and the signature still verifies.

## Selectors

A selector locates the public key in DNS:

```text
mail2026._domainkey.example.com   TXT   v=DKIM1; k=rsa; p=<base64 public key>
```

Date-based selectors (`mail202609`) make key age obvious in a zone file, which is exactly what
an operator needs when deciding whether a rotation is overdue. `DkimSelector.CreateDateBased`
generates them.

## Rotation

Never a hard swap — in-flight mail signed with the old key must still verify.

```text
Generate  →  Publish the new key in DNS  →  Verify propagation from several resolvers
          →  Activate signing with the new selector
          →  Wait out the grace window (at least the longest plausible delivery delay)
          →  Retire the old key
```

Retiring the old key before in-flight mail has been delivered turns valid mail into DKIM
failures at the receiver, which is worse than a slightly stale key.

## Private key storage

Encrypted through `ISecretProtector` (DPAPI with additional entropy) and never written to a
log. Because DPAPI is machine-scoped, DKIM keys are among the secrets re-wrapped under a
passphrase-derived key at backup time — see `docs/BackupRestore.md`. Losing them means every
signature stops verifying until new keys propagate.

## Verification (inbound)

Every signature on a message is verified; a message may legitimately carry several. Only
`rsa-sha256` with `relaxed/relaxed` canonicalisation is accepted — anything else (`simple`
canonicalisation, `rsa-sha1`, an unrecognised algorithm) is a permanent verification failure for
that signature, never treated as a pass. The result feeds DMARC alignment: DKIM passes for DMARC
only if the `d=` domain aligns with the `From` header domain, extracted by
`FromHeaderDomain` — which refuses to name a domain at all (not "picks one") when the `From:`
field names more than one mailbox or the message carries more than one `From:` field, per RFC
7489 §6.6.1. A malformed `t=`/`x=` timestamp outside the representable date range fails only
that one signature, not the whole message.

## The canonicalisation trap

Relaxed **body** canonicalisation is unforgiving about trailing whitespace and trailing empty
lines. One byte wrong and every signature this server produces fails verification everywhere —
silently, at the receiver, with no error visible locally. This is tested against RFC 6376 §3.4.5's
official canonicalization example; it has **not** been verified against real signed mail from
Gmail or Microsoft 365 — that needs a public IP and a live exchange, which a build agent does not
have (the same caveat `docs/Standards.md` records for every standard in this milestone).

## What is not built yet

* **No operator-facing way to provision a key.** `DkimKeyGenerator`, `DkimKeyRepository` and the
  signing/verification pipeline are all built and tested, but nothing — no IPC command, no WPF
  screen — currently calls `DkimKeyGenerator.Generate` and activates the result for a domain.
  Today a key can only reach the database through a test or a direct insert. Exposing this is
  necessary before any real domain can actually sign outbound mail.
* **Key rotation is a documented procedure, not automation.** The steps above are what an
  operator (or a future scheduled job) must do by hand today.
* **Ed25519 (RFC 8463)** is not implemented — see below.

## Ed25519

RFC 8463 Ed25519 signatures are cheap to add alongside RSA and increasingly recognised.
Recommended as a **secondary** signature in a later milestone — publishing only Ed25519 would
fail at receivers that do not support it.
