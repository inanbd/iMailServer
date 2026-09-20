# Mail Standards — Implementation Status

**Rule for this document: nothing is marked Implemented until it has passing tests.**
"It compiles" is not implemented. "It worked once by hand" is not implemented. Overstating
compliance in a mail server is worse than understating it, because operators make deployment
decisions from this table.

Status values:

| Status | Meaning |
|---|---|
| **Implemented** | Built, covered by automated tests, and exercised against a real peer where applicable |
| **Partial** | Built and tested for a defined subset; the gaps are named explicitly |
| **Planned** | Designed, scheduled to a milestone, not yet built |
| **Not applicable** | Deliberately out of scope, with the reason given |

---

## Transport and message format

> **What "exercised against a real peer" has meant so far.** The Milestone 6 and 7 rows were
> verified against the running service over a real TCP socket and a real TLS handshake. Milestone
> 6 used a hand-written SMTP client; Milestone 7 used **Python's `smtplib`**, an independent
> client library that does its own EHLO parsing, STARTTLS and AUTH negotiation — a real peer in
> the sense that it is somebody else's implementation of the protocol, not in the sense that it
> is Gmail or Outlook. **This server has not yet exchanged mail with Google
> Workspace, Microsoft 365, Yahoo, iCloud or Proton Mail**, because that needs a public IP, a
> PTR record and a publicly trusted certificate, none of which a build agent has. Those rows say
> Implemented because the standard is implemented and tested; they do not say the server has
> been proven to interoperate, and nothing here should be read as a claim about inbox placement.

| Standard | RFC | Status | Milestone | Notes |
|---|---|---|---|---|
| SMTP / ESMTP | 5321 | **Partial** | 6–8 | Receipt, submission and outbound delivery are all built and tested end to end over a real socket, including AUTH and a full EHLO/STARTTLS/MAIL/RCPT/DATA client conversation. `BDAT`/`CHUNKING` is not advertised on either side, and a message that used `SMTPUTF8` addressing on the way in is not yet re-advertised on the way out — see the `SMTPUTF8` row. See `docs/SMTP.md` |
| Internet Message Format | 5322 | **Partial** | 6 | The `Received:` trace header is generated, folded correctly, and every client-supplied field is sanitised and length-bounded against header injection. **Full message parsing is still not built** — MimeKit is not yet referenced and no MIME tree is walked — but IMAP's `ENVELOPE` now parses the RFC 2822 header into fields and `address-list`s into address structures, per RFC 3501 §7.4.2. RFC 2822 §A.5's deliberately awkward example is a test |
| Message Submission | 6409 | **Implemented** | 7 | Port 587 with STARTTLS-before-AUTH and port 465 with implicit TLS, both enabled by default. Verified with Python's `smtplib` — an independent client library doing its own EHLO parsing, STARTTLS and AUTH negotiation. A sender may use its own address or an alias it is behind, and nothing else |
| MIME (parts 1–5) | 2045–2049 | **Partial** | 10 | Via MimeKit; not hand-rolled. Still nothing parses MIME — receipt and submission are byte-transparent, which is why they can be correct without it. **Milestone 9 did not turn out to need it after all**: DKIM canonicalization and header inspection only ever needed to find the header/body boundary and read individual header fields, which `RawMessageHeaders` (a small, hand-rolled, Domain-layer parser — deliberately not MimeKit, since Domain cannot reference third-party packages) does without understanding MIME structure at all. The first real consumer is IMAP `BODY[…]` part addressing in Milestone 10 — see `docs/Architecture.md`'s A9 addendum — and it is now built: a hand-rolled Domain-layer MIME reader takes a stored message apart into the structure RFC 3501 §7.4.2 describes, applying RFC 2045 §5.2's and §6.1's defaults and RFC 2046 §5.1.5's digest default, and honouring §5.1.1's rule that the CRLF before a boundary belongs to the boundary. Not built: transfer-decoding, RFC 2047 word decoding and RFC 2231 parameter reassembly, none of which a server owes an IMAP client. **One deliberate strictness**: an *opening* boundary delimiter must be the whole line, per RFC 2046 §5.1.1's BNF, rather than the prefix match its note to implementors permits — the note's reading would make `--xy` match a declared boundary of `x` and cut a nested multipart in half. A *closing* delimiter with trailing text is accepted, because missing one leaks the epilogue into the last part; see `docs/IMAP.md` |
| SMTP Service Extension for SIZE | 1870 | **Implemented** | 6 | Advertised per-connection from the effective limit; a declared size over the limit is refused at `MAIL FROM`, and the real size is counted during DATA and charged against raw octets |
| PIPELINING | 2920 | **Implemented** | 6 | Advertised and honoured: the reader hands the DATA pump a window and keeps what it does not consume, so a command sharing a packet with the end-of-data marker is not lost. Pipelining across STARTTLS closes the connection — see `docs/SMTP.md` |
| 8BITMIME | 6152 | **Implemented** | 6 | Receipt is byte-transparent; the decoder rewrites line endings and transparency dots and nothing else |
| CHUNKING / BDAT | 3030 | Planned | Post-7 | Exact byte counting, `LAST` semantics. Not advertised, so no peer attempts it |
| ENHANCEDSTATUSCODES | 3463 | **Implemented** | 6 | Every reply carries one, paired with its code in a single vocabulary so the two cannot drift apart at a call site |
| DSN (delivery status notifications) | 3461, 3464 | **Partial** | 8 | Generated on permanent failure and on a configurable delay-warning threshold, addressed with the null reverse path and never generated for a message that itself has one (bounce-loop prevention). **Single-part `text/plain`, not RFC 3464's `multipart/report`** — that needs a MIME *writer*, which is still unbuilt (see the MIME row). Detecting an *inbound* `Auto-Submitted` header to suppress a DSN is still not implemented, but no longer because of a MIME dependency: Milestone 9's `RawMessageHeaders`/`MessageHeaderReader` can read any header, including `Auto-Submitted`, without understanding MIME structure at all — this is simply not wired into DSN generation yet, a smaller remaining gap than originally scoped. Only the null-reverse-path half of loop prevention is enforced today |
| SMTPUTF8 | 6531, 6532, 6533 | **Partial** | Post-7 | Address model complete and tested (`EmailAddress`, `DomainName` round-trip Unicode ↔ punycode without loss) and the SMTP path parser preserves it. The transport-level extension is still **not advertised**, so nothing downgrades yet. It did not land in Milestone 7 and is not claimed to have |
| IDNA 2008 | 5890, 5891 | **Implemented** | 1 | `DomainName` normalises to A-labels and preserves U-labels; 20 tests |

---

## Transport security

| Standard | RFC | Status | Milestone | Notes |
|---|---|---|---|---|
| STARTTLS for SMTP | 3207 | **Implemented** | 6 | Full session-state reset after the handshake, verified over a real TLS handshake on a real socket. Octets pipelined before the handshake close the connection; a reflection test requires every piece of session state to be classified as cleared or deliberately surviving |
| Implicit TLS for submission | 8314 | **Implemented** | 7, 10 | **Ports 465, 993 and 995 are all implemented and tested.** §3 prefers implicit TLS over `STARTTLS`/`STLS` for all three: there is no cleartext phase for a stripping attacker to interfere with |
| MTA-STS | 8461 | Planned | 11 | Policy served over HTTPS by the in-process Kestrel |
| TLS-RPT | 8460 | Planned | 11 | Report ingestion and analysis |
| REQUIRETLS | 8689 | Planned | 11 | Fails rather than downgrading when the policy cannot be met |
| DANE for SMTP | 7672 | **Planned (gated)** | Post-13 | **Deliberately not enabled without DNSSEC validation.** `IDnsResolver` exposes an authenticated-data flag so this can be switched on honestly later; claiming DANE without validation would be actively harmful |
| ACME v2 | 8555 | Planned | 4 | Via Certes; HTTP-01 and DNS-01 |

---

## Authentication

> **What "tested" has meant for the Milestone 9 rows.** SPF, DKIM and DMARC are tested against
> their own RFC's official examples (RFC 7208 Appendix A, RFC 6376 §3.4.5, RFC 7489 Appendix
> B.1) and against this product's own round-trip (its signer verifies against its own verifier,
> its evaluator checked against a fake DNS zone). **None of it has been exchanged with a real
> mail provider** — the same "not yet exercised against a live peer" caveat as the Milestone 6–8
> rows above, for the same reason (no public IP, no PTR record, no publicly trusted certificate
> available to a build agent). A future milestone's exit criterion — "Google/Microsoft report
> SPF+DKIM+DMARC pass" (`docs/Architecture.md` §27) — is therefore still open, independent of
> these rows saying Implemented/Partial.

| Standard | RFC | Status | Milestone | Notes |
|---|---|---|---|---|
| SASL PLAIN | 4616 | **Implemented** | 7 | Offered only over TLS, on submission listeners only, never on port 25. The password is held in a clearable buffer from the wire to Argon2 and overwritten immediately afterwards |
| SASL LOGIN | (de facto) | **Implemented** | 7 | Same conditions as PLAIN. Offered solely because Outlook and others support it and not PLAIN; it is strictly worse — an extra round trip and no authorization identity |
| SCRAM-SHA-256 | 7677 | Planned | Post-7 | Architected for; not in the initial submission work |
| OAUTHBEARER | 7628 | Planned | Post-7 | |
| SPF | 7208 | **Implemented** | 9 | Parser, evaluator and DNS resolver, tested against every example in RFC 7208 Appendix A's official DNS zone. Enforces the 10-lookup/2-void-lookup limits as `permerror`, with one shared budget across nested `include`/`redirect` recursion. Macro expansion (`%{s}`, `%{i}`, …) is a deliberate non-goal — a directive using one is `permerror`, never evaluated unexpanded. The `ptr` mechanism is recognised but never queried or matched, per RFC 7208 §5.5's own recommendation against publishing it |
| DKIM | 6376 | **Partial** | 9 | RSA-2048/3072/4096-SHA-256, relaxed/relaxed only; `From` oversigned; `l=` omitted; tested against RFC 6376 §3.4.5's official canonicalization vectors and round-tripped through this product's own signer/verifier. **Not built: any operator-facing command to generate a key and activate it for a domain** — `DkimKeyGenerator` exists and is tested, but nothing currently calls it outside a test; a key can only reach the database through a test or a direct insert. `DkimKeyRepository` is not in the same position — `OutboundSmtpClient` calls its `GetActiveForDomainAsync`/`GetPrivateKeyAsync` on every real outbound delivery — it is simply that nothing has ever inserted an active key for it to find. Simple canonicalization and `rsa-sha1` are correctly rejected as unsupported, never silently accepted |
| DKIM Ed25519 | 8463 | Planned | Post-9 | Recommended as a secondary signature |
| DMARC | 7489 | **Partial** | 9 | Policy discovery (exact domain, one fallback to the organizational domain per §6.6.3), alignment and `pct=`-sampled `p=reject` enforcement at the SMTP level, tested against RFC 7489 Appendix B.1's official alignment examples. Organisational-domain resolution uses a real embedded Public Suffix List snapshot (see `docs/DMARC.md`), refreshed by replacing the embedded file and rebuilding — **not yet an automated or scheduled refresh**. **Not implemented: aggregate (`rua=`) and failure (`ruf=`) reporting** — this product records its own per-message verdict, not reports from other receivers about its own domains' mail. `p=quarantine` is evaluated and recorded identically to `p=reject` but does not route mail anywhere different; only `p=reject` is actually enforced |
| ARC | 8617 | **Partial** | 9 | Groundwork only: `ArcChain.Parse` structurally parses and groups `ARC-Seal`/`ARC-Message-Signature`/`ARC-Authentication-Results` headers by instance, checking well-formedness (contiguous instances, a correctly placed `cv=none`). **No cryptographic seal or signature validation** — nothing here lets an ARC chain rescue a message that fails DMARC on its own. A security test asserts no SPF/DKIM/DMARC decision reads an ARC header's claims as its own verdict |
| Authentication-Results header | 8601 | **Partial** | 9 | `AuthenticationResultsComposer` formats this server's own SPF/DKIM/DMARC verdicts into a header value, tested in isolation. **Not attached to any served message**, and `AuthenticationResultsComposer` has no production caller at all, so there is still nothing to strip an untrusted upstream's copy from. An earlier revision of this row named IMAP `FETCH` as the first consumer; that was the wrong seam, and the reason is an ordering constraint worth recording. The `Received:` preamble is built at the *start* of `DATA` (`SmtpConnectionHandler.BuildPreamble`), where only the SPF outcome exists — DKIM needs the whole body, so `LocalDeliveryService.DeliverAsync` verifies DKIM and DMARC only after the content is written and `MessageRecord.Create` has already fixed `SizeBytes` and `ContentHash`. There is therefore no point in the current inbound flow where a complete SPF+DKIM+DMARC header can simply be prepended: stamping it means rewriting stored content and recomputing both, and synthesising it at `FETCH` time instead would break the byte-for-byte agreement between `BODY[]`, `RFC822.SIZE` and the `BODYSTRUCTURE` offsets. The verdicts remain queryable as `DkimVerificationRecord`/`DmarcVerificationRecord` rows beside the message. **Deferred to Milestone 11**, where the header analyser is the natural home |
| SRS (Sender Rewriting Scheme) | (de facto) | Planned | Post-9 | HMAC-authenticated, time-limited envelope rewriting |

---

## Mailbox access

| Standard | RFC | Status | Milestone | Notes |
|---|---|---|---|---|
| IMAP4rev1 | 3501 | Partial | 10 | UID and UIDVALIDITY correctness is the priority. **Folder-name case matching diverges by provider** — exact on SQLite, case-insensitive on a default-collation SQL Server; see `docs/IMAP.md`. `CAPABILITY`, `NOOP`, `LOGOUT`, `STARTTLS`, `LOGIN`, `AUTHENTICATE`, `SELECT`, `EXAMINE`, `LIST`, `LSUB`, `STATUS`, `FETCH`, `STORE`, `EXPUNGE`, `CLOSE`, `CHECK`, `CREATE`, `DELETE`, `RENAME`, `SUBSCRIBE`, `UNSUBSCRIBE`, `COPY`, `APPEND`, `SEARCH` and `IDLE` are implemented; `FETCH` serves every data item §6.4.5 defines — the stored columns, `ENVELOPE`, `BODY`, `BODYSTRUCTURE`, every `BODY[…]` section including numbered MIME parts, the `RFC822*` equivalents, partials and the `.PEEK` forms — and all three macros. Everything else is answered with a tagged `NO` naming the command rather than pretended at. §6.4.6's last-paragraph SHOULD — an untagged `FETCH` when an external source changes a message's flags — **is met** for an idling session, through `ImapFlagWatch`. **§4.3's literals are read for every command**, not only `APPEND`: the connection answers a trailing specifier, takes the octets and joins the rest of the line on, so a mailbox name, a userid or a `SEARCH` term may arrive as octets — `ImapCommand.Literals` carries the values and `ImapAstringReader` matches them to their specifiers positionally. `APPEND`'s message literal is the deliberate exception, streamed to the message store rather than held in memory. Caps bound it: 4096 octets per literal, 32 literals and 64 KiB per command; see `docs/IMAP.md` |
| IMAP IDLE | 2177 | **Implemented** | 10 | Pushes untagged `EXISTS` from a five-second folder poll. Advertising IDLE without real pushes would be worse than not advertising it: §3 tells a client that without the capability it "must poll", so a silent IDLE makes it see mail later. The baseline is the count the client was last told, so a delivery between `SELECT` and `IDLE` is pushed and an unreported shrink never lowers it — RFC 3501 §7.4.1 pairs a falling count with `EXPUNGE` lines, which a poll cannot produce |
| IMAP NAMESPACE | 2342 | **Implemented** | 10 | One personal namespace, no prefix, `/` delimiter — RFC 2342 Example 5.1. §4 makes the capability atom a MUST |
| IMAP UNSELECT | 3691 | **Implemented** | 10 | CLOSE without the expunge. §1: the capability atom is how a client discovers it |
| IMAP CHILDREN | 3348 | **Implemented** | 10 | `\HasChildren`/`\HasNoChildren` on every `LIST` line, derived once per folder set rather than per folder. Unlike RFC 6154 below, this one **needs a capability**: §3 says a server supporting it "MUST list the keyword CHILDREN in their CAPABILITY response" — same command, two extensions, opposite answers |
| IMAP SPECIAL-USE | 6154 | **Implemented** | 10 | Stops clients creating duplicate Sent folders. Note RFC 6154 §2: the attributes need **no capability** on the non-extended `LIST`; the `SPECIAL-USE` atom instead commits a server to RFC 5258 LIST-EXTENDED, so this product emits the attributes and advertises nothing |
| IMAP MOVE | 6851 | **Implemented** | 10 | One repository method serves COPY and MOVE, because §3.3 defines the second in terms of the first. No `\Deleted` flag is ever set — §3.3 forbids it — and `[TRYCREATE]` applies to both |
| IMAP LITERAL- | 7888 | **Implemented** | 10 | **`LITERAL-`, not `LITERAL+`.** RFC 7888 defines both; `LITERAL-` caps a non-synchronising literal at 4096 octets and `LITERAL+` places no bound on one, and §5 forbids advertising both. This product requires a hard cap — `{n+}` lets a client push bytes before the server can refuse — so it was never a `LITERAL+` server. The atom is advertised, and `ImapConnectionHandler.MaxInlineLiteralOctets` is the 4096-octet cap that makes advertising it true rather than decorative — a server announcing it and then reading an unbounded `{n+}` would be a `LITERAL+` server under another name. The cap applies to the synchronising form too, which §4 does not require and which costs nothing: the arguments that arrive as literals are mailbox names, userids and search text. The two refusals differ as §4 says they must — a synchronising literal over the cap is refused with a tagged `BAD` and no continuation, so its octets never leave the client, while a non-synchronising one is already in flight and takes §4's untagged `BYE`. Advertising the cap is what makes that second path nearly unreachable: a client that has read the capability sends a synchronising literal above it |
| POP3 | 1939 | **Implemented** | 10 | **Disabled by default**, for legacy devices only — destructive reads interact badly with IMAP on the same mailbox, and §8 records what a maildrop becomes when clients use it as a repository. Every minimal command (`USER`, `PASS`, `QUIT`, `STAT`, `LIST`, `RETR`, `DELE`, `NOOP`, `RSET`) plus the optional `TOP` and `UIDL`. Deletions live in the session and are committed only by a `QUIT` from TRANSACTION, which is §6's MUST: a dropped connection removes nothing. The maildrop is the mailbox's INBOX, and §4's exclusive-access lock is process-local — see `docs/POP3.md`. `APOP` is refused by name: its digest needs a secret this server cannot recover from a password verifier, and §6 of RFC 2449 makes a greeting with no angle brackets the signal not to try |
| POP3 extension mechanism (CAPA) | 2449 | **Implemented** | 10 | Required by RFC 2595 §4 for any server offering `STLS`. Announces `TOP`, `UIDL`, `RESP-CODES`, `PIPELINING`, `IMPLEMENTATION`, and `USER` only once a password may be sent safely — the POP3 counterpart of IMAP's `LOGINDISABLED`, for which §6.2's `USER` capability is the only vocabulary POP3 has. There is deliberately no `APOP` capability; §6 says why |
| POP3 STLS | 2595 | **Implemented** | 10 | §4's upgrade on port 110. Buffered input at the handshake is refused as the CVE-2011-0411 command-injection pattern, exactly as IMAP's `STARTTLS` is, and the reader is replaced rather than reused |

---

## Operational

| Standard | RFC | Status | Milestone | Notes |
|---|---|---|---|---|
| One-Click Unsubscribe | 8058 | Planned | 11 | Cryptographically secure tokens; no internal ids exposed |
| List-Unsubscribe header | 2369 | Planned | 11 | |
| Auto-Submitted header | 3834 | **Partial** | 8 | Every generated DSN carries `Auto-Submitted: auto-replied`. Reading the header on an *inbound* message to decide whether to bounce it is not implemented. The header-reading capability this needs now exists (`RawMessageHeaders`, Milestone 9) — this is unwired application logic, not a missing parser; today's bounce-loop prevention relies solely on the null reverse path, which is the more load-bearing of the two rules regardless |
| Reverse DNS / FCrDNS | 1912 (BCP) | Planned | 11 | Checked and scored, not merely documented |
| Null MX | 7505 | **Implemented** | 8 | A domain publishing a single `0 .` record is treated as an immediate permanent failure, never a retry |

---

## Implemented in Milestone 1

These, and the Milestone 2 entries below, are the only entries currently backed by tests.

| Capability | Evidence |
|---|---|
| IDNA 2008 domain normalisation | `DomainNameTests` — 20 tests including punycode round-trip, label limits, subdomain matching that rejects bare-suffix lookalikes |
| RFC 5321 address grammar | `EmailAddressTests` — 21 tests including quoted local-parts, the full atext set, octet limits, control-character and CRLF rejection |
| Retry backoff policy | `RetryBackoffPolicyTests` — 12 tests including jitter bounds and rejection of a non-ascending schedule |
| Schema migration guarantees | `MigrationRunnerTests` — 10 tests including checksum drift, idempotency, WAL and foreign-key verification |
| SQLite concurrency model | `TransactionTests` — 9 tests including 8 concurrent writers and a reader unblocked by an open write transaction |
| IPC framing and command allow-list | `IpcFrameTests`, `IpcCommandRegistryTests` — 23 tests including oversized-length rejection before allocation |
| IPC end to end | `IpcEndToEndTests` — 10 tests over a real named pipe with the real pipeline |
| Clean Architecture dependency rule | `ArchitectureTests` — fails the build if `MailServer.Domain` references anything but the BCL |

---

## Implemented in Milestone 2

| Capability | Standard | Evidence |
|---|---|---|
| Argon2id password hashing | RFC 9106 | `PasswordHashingTests` — 16 tests including PHC round-trip, work-factor upgrade detection, and a timing bound proving a missing account and an empty candidate both spend the full cost |
| Password policy | NIST SP 800-63B (length and blocklist, no composition rules) | `PasswordHashingTests`, `PasswordPolicyTests` |
| Escalating lockout | — | `LockoutAndBruteForceTests` — 13 tests including doubling, the cap, the counter reset window, and lockout surviving a restart |
| Recovery key | Crockford base32, 125 bits | `RecoveryKeyTests` — 12 tests including single use, lockout bypass, and rejection of the ambiguous characters |
| Authentication end to end | — | `AuthenticationFlowTests` — 25 tests against real SQLite, real migrations, real Argon2 and the real pipeline |
| Secret storage | — | `SecretStoreTests` — 9 tests including a direct read of the stored column proving the plaintext never reaches the database |
| IPC session enforcement | — | `IpcEndToEndTests` — every session-requiring command in the registry is refused without a token and with a forged token; the four anonymous commands are proved reachable |

---

## Implemented in Milestone 3

| Capability | Standard | Evidence |
|---|---|---|
| Self-signed certificate generation | RFC 5280 (extensions), RFC 6125 (naming) | `SelfSignedGenerationTests` — 27 tests reading SANs, EKU, basic constraints, key usage and SKI back out of the generated certificate |
| subjectAltName matching | RFC 6125 §6.4.3 | `CertificateSubjectNameTests` — wildcard replaces exactly one label; partial-label wildcards and whole-TLD wildcards refused |
| Certificate hot reload | — | `CertificateLifecycleTests` — a renewed certificate takes effect without a restart, and a certificate read before a reload stays usable after it |
| SNI selection and fallback | RFC 6066 | `CertificateLifecycleTests` — per-hostname selection, case-insensitive matching, and the default served when no SNI is offered |
| Chain validation with no bypass | — | `NoCertificateValidationBypassTests` — scans every production source file; verified to fail on a deliberately introduced bypass |
| Certificate storage | PKCS#12 | `CertificateLifecycleTests` — the stored file cannot be opened without the passphrase, and the passphrase is not in the key location |
| Expiry escalation | — | `CertificateRenewalPolicyTests` — thresholds, the lowest-crossed rule, and the never-downgrade property |

---

## Implemented in Milestone 4

| Capability | Standard | Evidence |
|---|---|---|
| ACME v2 client | RFC 8555 | `IssuanceTests` — the full sequence against a fake CA at the `IAcmeClient` seam; **not** verified against Let's Encrypt, see `docs/LetsEncrypt.md` |
| HTTP-01 challenge | RFC 8555 §8.3 | `IssuanceTests` — publication and cleanup; the Kestrel endpoint verified at runtime to serve 404 for unknown tokens |
| DNS-01 challenge | RFC 8555 §8.4 | `IssuanceTests` — record published and removed, and the manual path proved to stop before asking the CA to validate |
| DNS TXT lookup | RFC 1035 | `DnsTxtParsingTests` — 11 tests including truncation at every offset, a self-referential compression pointer, and rdata claiming to run past the buffer |
| Rate-limit awareness | Let's Encrypt published limits | `RateLimitTests` — 9 tests; `IssuanceTests` proves local refusals do not count towards the limit |
| Pre-flight refusal | — | `IssuanceTests` — a blocking finding stops the order before the CA sees it |
| Automatic renewal | — | `IssuanceTests` — the issued certificate satisfies the renewal loop's own filter, and reissuing repoints the existing binding |
| Migration directive parsing | — | `MigrationDirectiveTests` — a comment mentioning `@Destructive` no longer becomes it |

---

## Implemented in Milestone 5

| Capability | Standard | Evidence |
|---|---|---|
| Mailbox quota inheritance and enforcement | — | `QuotaTests` — 22 tests including the exact-fill boundary, the clamp at zero, and lowering a quota below current usage |
| Role addresses | RFC 2142, RFC 5321 §4.5.1 | `MailboxAdministrationTests` — a new domain reports `postmaster@` missing, and an alias satisfies it |
| IMAP SPECIAL-USE folders | RFC 6154 | `MailboxAdministrationTests` — the standard six are provisioned at creation with one inbox |
| Alias expansion bounds | — | `AliasExpansionPolicyTests` — 12 tests including a two-alias cycle, a self-reference, and an exponentially branching graph |
| Mailbox credentials | RFC 9106 (Argon2id) | `MailboxAdministrationTests` — the stored column is read directly and asserted to be a PHC verifier, not the password |
| Address uniqueness across mailboxes and aliases | — | `MailboxAdministrationTests` — refused in both directions |
| Full mailbox and alias CRUD | — | `MailboxAdministrationTests` — 42 tests through the real pipeline; `IpcEndToEndTests` proves all 11 new commands require a session |

---

## Implemented in Milestone 8

| Capability | Standard | Evidence |
|---|---|---|
| MX resolution, implicit MX, null MX | RFC 5321 §5.1, RFC 7505 | `DnsMxResolverTests` — 10 tests including NXDOMAIN/SERVFAIL classification, the implicit fallback to a domain's own A record, and a single `0 .` record refused as an immediate permanent failure |
| MX preference ordering | RFC 5321 §5.1 | `MxSelectionPolicyTests` — ascending preference band, shuffled within a band, every host returned exactly once |
| Outbound SMTP client | RFC 5321 | `OutboundSmtpClientTests` — 10 tests over a real loopback socket against a fake remote MX: acceptance, 5xx/4xx classification, a body line that is itself a bare dot surviving dot-stuffing, and a closed port failing as temporary rather than throwing |
| Opportunistic and required STARTTLS (client side) | RFC 3207, this product's outbound TLS policy (`docs/TLS.md`) | `OutboundSmtpClientTests` — encrypts and records an untrusted certificate's subject/issuer when TLS is opportunistic; refuses to fall back to plaintext, whether the certificate was untrusted or STARTTLS was never offered, when TLS is required |
| No certificate validation bypass (outbound client) | — | `NoCertificateValidationBypassTests`, plus a dedicated test that the callback calls the real chain validator rather than a rubber stamp |
| Queue leasing and reclaim | — | `OutboundQueueRepositoryTests` — 11 tests including two workers racing for the same item, a deferred item becoming claimable exactly at its next-attempt time, and a crashed worker's lease being reclaimed only after it expires |
| Retry backoff, bounce, DSN, delay warning | RFC 3461/3464 (partial — see the Standards table), RFC 3834 (partial) | `OutboundDeliveryHostedServiceTests` — 8 tests including the exact retry interval, a permanent failure generating a DSN addressed to the original sender, a null-reverse-path message never generating one, MX failures short-circuiting the delivery client entirely, maximum-lifetime expiry, and a delay-warning DSN sent once and never repeated |




---

## Known gaps and risks

* **PIPELINING with STARTTLS** is the highest-risk interaction in the SMTP work. Every
  plaintext byte buffered before the handshake must be discarded; failing to do so is the
  STARTTLS command-injection class of bug (CVE-2011-0411 and relatives). A dedicated security
  test is budgeted for Milestone 6.
* **DKIM relaxed body canonicalisation** is unforgiving about trailing whitespace and trailing
  empty lines. One byte wrong and every signature fails verification everywhere. RFC 6376 test
  vectors plus real signed mail are budgeted for Milestone 9.
* **DMARC organisational-domain resolution** needs a current Public Suffix List. A stale list
  silently inverts alignment results, so its age is a health check rather than an assumption.
* **IMAP UID correctness** causes silent mail loss in clients when wrong. Allocation happens
  inside the insert transaction with a unique constraint, and interoperability testing against
  three real clients is an explicit Milestone 10 exit criterion.
* **Outbound delivery has not exchanged mail with a real Internet mail exchanger.**
  `OutboundSmtpClientTests` proves the client speaks correct SMTP and TLS against a fake MX over
  a real socket, the same rigor Milestone 4's ACME tests used against a fake CA; it has not been
  run against a live provider, because that needs a public IP, PTR-clean address space and
  outbound port 25, none of which a build agent has. See the port-25 warning in the README.
* **No smarthost / relay-via-upstream mode.** Every outbound message connects directly to the
  recipient's own MX. `docs/Architecture.md` risk 2 recommends smarthost delivery as a
  first-class mode for the (common) case where outbound port 25 is blocked; the request path
  (`OutboundDeliveryRequest` names an explicit host and port) does not preclude adding it, but
  nothing in this milestone builds it.
* **A retry-storm is possible only in the sense that nothing has proven it isn't.** The backoff
  schedule, jitter and per-domain concurrency cap are all unit-tested individually;
  `OutboundDeliveryHostedServiceTests` proves the worker calls them correctly, not that a
  production-scale backlog against a slow or hostile destination behaves acceptably under load.

---

*Last updated at the completion of Milestone 8.*
