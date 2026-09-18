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

## Listing mailboxes

`LIST` and `LSUB` share one handler and one matcher, because RFC 3501 §6.3.9 says their
arguments "are in the same form as those for LIST" — what differs is which folders are eligible
and the keyword on the untagged line.

**Patterns are matched in memory, not in SQL.** `%` must not cross the hierarchy delimiter,
which `LIKE`'s `%` cheerfully does, and a folder name may itself contain `%` or `_` — `LIKE`
metacharacters whose `ESCAPE` syntax differs between providers. Pushing the pattern into SQL
would mean a second, subtly different matcher living in two dialects. There is one matcher,
`ImapMailboxPattern`, and it has tests.

**The matcher is a dynamic-programming table rather than a regular expression**, which is a
security decision. A pattern is text an authenticated client chose, and translating it into a
regex would hand that client an exponential-backtracking denial-of-service vector. The table is
`O(pattern x name)` with no backtracking, so the worst case is arithmetic rather than a cliff,
and bounding the pattern's length bounds the cost.

**A trailing `%` reports hierarchy levels that are not mailboxes.** RFC 3501 §6.3.8 requires it:
a mailbox holding only `Projects/2026/Q1` answers `LIST "" "%"` with `Projects`, flagged
`\Noselect`. Omitting it would show the client a tree with the trunk missing and the leaf
unreachable.

**`LSUB` has the same rule as a MUST, and it is stranger.** §6.3.9: if `foo/bar` is subscribed
but `foo` is not, `LSUB "" "%"` "must return foo … and it MUST be flagged with the `\Noselect`
attribute" — even when `foo` is a real, selectable mailbox. In `LSUB` the attribute reports
absence from the subscription list rather than unselectability. §6.3.9 also tells clients that
"the flags in the untagged LIST are considered more authoritative", which is the escape hatch
that makes the overload safe.

**`CHILDREN` is advertised, and it has to be.** RFC 3348 §3: "IMAP4 servers that support this
extension MUST list the keyword CHILDREN in their CAPABILITY response." This is the opposite of
the special-use case below — same command, two extensions, two different answers about whether
a capability is needed. `\HasChildren` is derived once for the whole folder set rather than per
folder, because §6.3.8 warns that "if each name requires 1 second of processing, then a list of
1200 names would take 20 minutes!"

**`\Marked` and `\Unmarked` are never sent.** Answering "interesting" needs a per-folder record
of when each was last selected, which nothing here keeps, and §7.2.2 sanctions the omission:
"the server SHOULD NOT send either `\Marked` or `\Unmarked`" when it cannot tell. §6.3.8 goes
further and asks a server not to go to the trouble.

**Known limitation: a subscription cannot outlive its folder.** §6.3.9 says "The server MUST NOT
unilaterally remove an existing mailbox name from the subscription list even if a mailbox by
that name no longer exists." Subscriptions are stored as a column on the folder row, so deleting
a folder drops its subscription. The deviation is not reachable until `DELETE` is implemented,
and the fix is a schema change — a subscription list of its own — rather than a handler change.

## STATUS

`STATUS` reports `MESSAGES`, `RECENT`, `UIDNEXT`, `UIDVALIDITY` and `UNSEEN` for a folder
without selecting it, and touches nothing: §6.3.10 requires that it "does not change the
currently selected mailbox, nor does it affect the state of any messages in the queried
mailbox".

**`UNSEEN` means two different things in two commands, and the server reads them with two
queries.** §6.3.10's `UNSEEN` is "the number of messages which do not have the `\Seen` flag
set"; §6.3.1's `* OK [UNSEEN n]` is the message *sequence number* of the first unseen message. A
mailbox whose first eleven messages are read and whose twelfth is not reports `[UNSEEN 12]` on
`SELECT` and `UNSEEN 1` on `STATUS`. Serving one from the other would be wrong by however many
read messages precede the first unread one.

`RECENT` is reported as a truthful zero. `\Recent` is reserved and never set by this server, so
the count of messages carrying it is zero — a true answer rather than an unimplemented one.

## IDLE

Held with a server-side timer that emits a keep-alive before the 29-minute RFC 2177 limit, and
cancelled cleanly on shutdown.

## POP3

Implemented for legacy device compatibility, **disabled by default**.

POP3's destructive-read model interacts badly with IMAP on the same mailbox: a POP3 client
that downloads and deletes removes mail the IMAP client expected to still be there. The admin
UI warns about this at the point of enabling it, not in a footnote.
