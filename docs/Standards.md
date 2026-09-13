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

| Standard | RFC | Status | Milestone | Notes |
|---|---|---|---|---|
| SMTP / ESMTP | 5321 | Planned | 6 | Explicit state machine; see `docs/SMTP.md` |
| Internet Message Format | 5322 | Planned | 6 | Via MimeKit |
| Message Submission | 6409 | Planned | 7 | Ports 587 and 465 |
| MIME (parts 1–5) | 2045–2049 | Planned | 6 | Via MimeKit; not hand-rolled |
| SMTP Service Extension for SIZE | 1870 | Planned | 6 | Advertised per-connection from the effective limit |
| PIPELINING | 2920 | Planned | 6 | Interacts with STARTTLS; see risk note below |
| 8BITMIME | 6152 | Planned | 6 | |
| CHUNKING / BDAT | 3030 | Planned | 6 | Exact byte counting, `LAST` semantics |
| ENHANCEDSTATUSCODES | 3463 | Planned | 6 | |
| DSN (delivery status notifications) | 3461, 3464 | Planned | 8 | Null reverse path; loop prevention |
| SMTPUTF8 | 6531, 6532, 6533 | **Partial** | 6 | Address model complete and tested (`EmailAddress`, `DomainName` round-trip Unicode ↔ punycode without loss); the transport-level extension lands in Milestone 6 |
| IDNA 2008 | 5890, 5891 | **Implemented** | 1 | `DomainName` normalises to A-labels and preserves U-labels; 20 tests |

---

## Transport security

| Standard | RFC | Status | Milestone | Notes |
|---|---|---|---|---|
| STARTTLS for SMTP | 3207 | Planned | 6 | Full session-state reset after the handshake |
| Implicit TLS for submission | 8314 | Planned | 7 | Ports 465, 993, 995 |
| MTA-STS | 8461 | Planned | 11 | Policy served over HTTPS by the in-process Kestrel |
| TLS-RPT | 8460 | Planned | 11 | Report ingestion and analysis |
| REQUIRETLS | 8689 | Planned | 11 | Fails rather than downgrading when the policy cannot be met |
| DANE for SMTP | 7672 | **Planned (gated)** | Post-13 | **Deliberately not enabled without DNSSEC validation.** `IDnsResolver` exposes an authenticated-data flag so this can be switched on honestly later; claiming DANE without validation would be actively harmful |
| ACME v2 | 8555 | Planned | 4 | Via Certes; HTTP-01 and DNS-01 |

---

## Authentication

| Standard | RFC | Status | Milestone | Notes |
|---|---|---|---|---|
| SASL PLAIN | 4616 | Planned | 7 | Offered only over TLS |
| SASL LOGIN | (de facto) | Planned | 7 | Offered only over TLS |
| SCRAM-SHA-256 | 7677 | Planned | Post-7 | Architected for; not in the initial submission work |
| OAUTHBEARER | 7628 | Planned | Post-7 | |
| SPF | 7208 | Planned | 9 | Enforces the 10-lookup and 2-void-lookup limits as `permerror` |
| DKIM | 6376 | Planned | 9 | RSA-2048/SHA-256; `From` oversigned; `l=` omitted by default |
| DKIM Ed25519 | 8463 | Planned | Post-9 | Recommended as a secondary signature |
| DMARC | 7489 | Planned | 9 | Requires the Public Suffix List for organisational-domain resolution |
| ARC | 8617 | Planned | 9 | Chain validation for forwarded mail |
| Authentication-Results header | 8601 | Planned | 9 | Untrusted upstream copies are stripped before ours is added |
| SRS (Sender Rewriting Scheme) | (de facto) | Planned | Post-9 | HMAC-authenticated, time-limited envelope rewriting |

---

## Mailbox access

| Standard | RFC | Status | Milestone | Notes |
|---|---|---|---|---|
| IMAP4rev1 | 3501 | Planned | 10 | UID and UIDVALIDITY correctness is the priority |
| IMAP IDLE | 2177 | Planned | 10 | Server-side timer below the 29-minute limit |
| IMAP SPECIAL-USE | 6154 | Planned | 10 | Stops clients creating duplicate Sent folders |
| IMAP MOVE | 6851 | Planned | 10 | |
| IMAP LITERAL+ | 7888 | Planned | 10 | Hard caps: `{n+}` lets a client push bytes before the server can refuse |
| POP3 | 1939 | Planned | 10 | **Disabled by default.** Destructive reads interact badly with IMAP on the same mailbox |

---

## Operational

| Standard | RFC | Status | Milestone | Notes |
|---|---|---|---|---|
| One-Click Unsubscribe | 8058 | Planned | 11 | Cryptographically secure tokens; no internal ids exposed |
| List-Unsubscribe header | 2369 | Planned | 11 | |
| Auto-Submitted header | 3834 | Planned | 8 | Central to bounce-loop prevention |
| Reverse DNS / FCrDNS | 1912 (BCP) | Planned | 11 | Checked and scored, not merely documented |
| Null MX | 7505 | Planned | 8 | Honoured as an immediate permanent failure |

---

## Implemented in Milestone 1

These are the only entries currently backed by tests.

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

---

*Last updated at the completion of Milestone 1.*
