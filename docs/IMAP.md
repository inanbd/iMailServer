# IMAP Architecture

> **Status: Planned — Milestone 10.**

## Why this is the riskiest subsystem

An IMAP server that gets UID semantics wrong causes clients to silently re-download mail or,
far worse, **delete it**. The failure is quiet, happens on the client, and destroys trust
permanently. It is the reason Milestone 10 has interoperability against three real clients as
an explicit exit criterion rather than a nice-to-have.

## Invariants

**UIDs are monotonically increasing per folder and never reused**, even after `EXPUNGE`.
Implemented as a per-folder `UidNext` counter allocated inside the same transaction that
inserts the message row, with a unique constraint on `(FolderId, Uid)`. Allocating it outside
the transaction would let two concurrent deliveries take the same UID.

**`UIDVALIDITY` changes only when UID continuity is genuinely broken** — the folder was deleted
and recreated, or restored from a backup that rewound UIDs. It is stored, never derived from a
timestamp at runtime. A `UIDVALIDITY` that changes spuriously makes every client discard its
local cache and re-download the mailbox.

**Sequence numbers are per-session and recomputed on expunge.** Untagged `EXPUNGE` responses
are emitted in **descending** sequence order so clients renumber correctly.

**No untagged `EXPUNGE` during `FETCH`, `STORE` or `SEARCH`** — forbidden by RFC 3501. Pending
expunges are queued and flushed at a permitted point. Sending one at the wrong moment makes
clients delete the wrong messages.

**`\Recent` is implemented conservatively.** Correct semantics require exactly one session to
own the flag, and most modern clients ignore it. Reporting conservatively beats reporting
incorrectly.

## Literals

`{n}` and `{n+}` need hard caps. Non-synchronising literals let a client push arbitrary bytes
**before the server can refuse**, which without a cap is a trivial memory exhaustion. Above a
threshold, literals stream to disk rather than to memory.

**The capability advertised for this is `LITERAL-`, not `LITERAL+`.** RFC 7888 defines both:
they permit the same `{n+}` syntax, but `LITERAL-` caps a non-synchronising literal at 4096
octets while `LITERAL+` places no bound on one at all, and §5 forbids advertising both at once.
Requiring a hard cap, as the paragraph above does, is the same thing as deciding this is not a
`LITERAL+` server. Advertising `LITERAL+` and then enforcing a cap anyway leaves only the two
exits RFC 7888 §4 spells out — read every declared byte and refuse the command regardless,
spending exactly the bandwidth an attacker wanted spent, or send an untagged `BYE` and drop the
connection, which §4 notes "some naive clients are known to blindly reconnect" from,
"introducing an infinite loop". That is a reconnect loop built into a denial-of-service defence.
`LITERAL-` states the cap up front instead, and a complying client sends a synchronising literal
above it — which the server can refuse before a single octet of it arrives.

## Special-use folders

`Inbox`, `Sent`, `Drafts`, `Trash`, `Junk`, `Archive` are created with the mailbox and the
RFC 6154 attributes (`\Sent`, `\Drafts`, `\Trash`, `\Junk`, `\Archive`) are returned for them,
so clients stop creating duplicates like `Sent Items` alongside `Sent`.

**No capability is advertised for this.** RFC 6154 §2 is explicit that the attributes need none
on the non-extended `LIST`; the `SPECIAL-USE` atom is about the *extended* `LIST` of RFC 5258,
and advertising it would commit this server to that command's selection and return options. So
the attributes are emitted and the atom is not — the whole benefit, with no promise attached.

## IDLE

Held with a server-side timer that emits a keep-alive before the 29-minute RFC 2177 limit, and
cancelled cleanly on shutdown.

## POP3

Implemented for legacy device compatibility, **disabled by default**.

POP3's destructive-read model interacts badly with IMAP on the same mailbox: a POP3 client
that downloads and deletes removes mail the IMAP client expected to still be there. The admin
UI warns about this at the point of enabling it, not in a footnote.
