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

## FETCH

Implemented for the data items that are stored columns — `FLAGS`, `UID`, `INTERNALDATE`,
`RFC822.SIZE`, and therefore the `FAST` macro in full. `ENVELOPE`, `BODY`, `BODYSTRUCTURE`,
`RFC822*` and `BODY[...]` need a MIME reader and are answered with a tagged `NO` naming the
item. RFC 3501 §6.4.5 distinguishes "BAD - command unknown or arguments invalid" from "NO -
fetch error: can't fetch that data"; a client told `BAD` for `ENVELOPE` would go looking for a
syntax error that is not there.

**`UID FETCH` is the same handler with one flag**, because §6.4.8 makes it the same command —
only what the numbers mean changes. Two of its rules are easy to get wrong and both are tested:

- *The number after the `*` is always a message sequence number*, "not a unique identifier, even
  for a UID command response". A server that echoed the UID there would have clients renumbering
  their caches against positions that do not exist.
- *The UID is included whether or not it was asked for.* §6.4.8 makes it a MUST, and without it
  a client that sent `UID FETCH 1:* FLAGS` has no way to tell which message each line is about.

**A message that is not there is passed over in silence.** §6.4.8: "A non-existent unique
identifier is ignored without any error message generated." A tagged `NO` would have a client
report a failure for a message it had already deleted.

**`INTERNALDATE` pads a single-digit day with a space, not a zero.** §9's `date-day-fixed =
(SP DIGIT) / 2DIGIT` is a fixed-width production, so the first of January is `" 1-Jan-2026
09:30:15 +0000"`. `"01-Jan"` is a string the grammar does not have.

**The sequence set is resolved by the reader, not before it.** `*` means "the largest in use",
and which largest depends on the command: `FETCH` resolves it against the message count and
`UID FETCH` against the largest UID. Both are facts about the folder at the instant of the read.

**A set with no `*` narrows the query; a set with one does not**, and that asymmetry is a
correctness requirement rather than a missed optimisation. §9 treats `5:3` and `3:5` alike, so a
folder holding four messages answers `6:*` as `6:4`, which is `4:6` — a read narrowed to "6 and
above" because 6 was written first would return nothing. The narrowing that does happen is a
single span covering every range, with exact filtering in memory: a set may hold up to 10,000
ranges, and turning those into a predicate would build a SQL string a client controls the length
of.

### Message content

`BODY[]`, `BODY[HEADER]`, `BODY[TEXT]`, `BODY[HEADER.FIELDS (…)]`, `BODY[HEADER.FIELDS.NOT (…)]`,
their `.PEEK` forms, `<origin.length>` partials, and the `RFC822`, `RFC822.HEADER` and
`RFC822.TEXT` items §6.4.5 defines as equivalents. Numbered MIME parts and `BODY[n.MIME]` are
refused by name pending the MIME tree; `ENVELOPE` and `BODYSTRUCTURE` likewise.

**The octets go out as a literal and are never touched.** §9 types a body section's value an
`nstring`, and a quoted string cannot hold CR, LF or an 8-bit octet — all of which a message is
full of. The response is therefore a *sequence*: server text, the octets verbatim, more server
text. Sanitising them would corrupt every attachment; re-encoding them as UTF-8 would corrupt
every message that is not UTF-8.

**An absent section is `NIL`, not `{0}`.** §9's `nstring` distinguishes them: `{0}` says the part
exists and is empty, `NIL` says there is no such part. A message whose octets are missing from
the store answers `NIL` rather than failing the command, so one damaged message does not make a
folder unopenable.

**A `BODY[…]` without `.PEEK` sets `\Seen`, and the response says so.** §6.4.5: "The \Seen flag
is implicitly set; if this causes the flags to change, they SHOULD be included as part of the
FETCH responses." The flag is set before the content is read back, so the flags reported are the
ones the message now has. `BODY.PEEK[…]` is "An alternate form […] that does not implicitly set
the \Seen flag", and an `EXAMINE`'d mailbox never acquires it either.

Note which `RFC822` forms peek: §6.4.5 makes `RFC822.HEADER` equivalent to `BODY.PEEK[HEADER]`
and `RFC822.TEXT` equivalent to `BODY[TEXT]`. Fetching a header alone does not mark a message
read; fetching its text does. The contrast is the RFC's.

**Header field subsets carry folded continuation lines.** RFC 2822 folds a long header onto
following lines beginning with whitespace, and a subset that kept the first line of a folded
`Subject` and dropped the rest would hand the client a truncated subject with no sign of it. The
blank line is always appended, per §6.4.5: "the blank line is always included as part of header
data, except in the case of a message which has no body and no blank line."

**Both line endings are accepted when splitting header from body.** A stored message that arrived
over SMTP is CRLF, but one written by another tool may be bare LF, and a scan recognising only
CRLF would treat such a message as all header and no body.

**Known limitation: a fetched message is read whole into memory.** The literal's octet count must
be known before the first byte goes out, so the content cannot be streamed without buffering it
anyway. That is per message rather than per folder, but a `FETCH 1:* BODY[]` over a large mailbox
still holds one message at a time on top of the materialised response below.

**Known limitation: the response is materialised, not streamed.** `FETCH 1:*` over a folder with
a million messages builds a million response objects before any of them is written. That is
within the current `ImapCommandResult` shape and is the next thing to change for large mailboxes.

## Folder management

`CREATE`, `DELETE`, `RENAME`, `SUBSCRIBE` and `UNSUBSCRIBE` share one handler, because they
differ only in which repository call they make and how many mailbox names they take. Every
failure is a tagged `NO`: RFC 3501 §6.3.3 phrases them as ordinary outcomes — "Any error in
creation will return a tagged NO response" — and a client creating a folder that already exists
has done something reasonable with stale information.

**`CREATE` builds the superior levels it needs** (§6.3.3's SHOULD) and drops a trailing
delimiter, which "is a declaration that the client intends to create mailbox names under this
name" and never part of the name. `INBOX` may be neither created nor deleted.

**`DELETE` leaves inferior names alone** — §6.3.4's MUST — and the deleted name then "will
acquire the `\Noselect` mailbox name attribute", which needs no code here: with the row gone the
name exists only as a hierarchy level, and a hierarchy level is exactly what this server reports
`\Noselect` for.

**`RENAME` carries the whole subtree** (§6.3.5's MUST), and renaming the inbox is a different
operation: "It moves all messages in INBOX to a new mailbox with the given name, leaving INBOX
empty. If the server implementation supports inferior hierarchical names of INBOX, these are
unaffected." The inbox survives, it is emptied, and its children stay put.

### Subscriptions are a table of names, not a flag on a folder

§6.3.6: a server "MUST NOT unilaterally remove an existing mailbox name from the subscription
list even if a mailbox by that name no longer exists", and the RFC's note gives the case — "a
server site can choose to routinely remove a mailbox with a well-known name (e.g.,
"system-alerts") after its contents expire, with the intention of recreating it when new contents
are appropriate."

A subscription stored on the folder row could not survive that, so `DELETE` would quietly
unsubscribe a user from a name they never gave up. Migration 0012 gives subscriptions their own
table, seeded from the column it supersedes. `MailboxFolders.IsSubscribed` is no longer read; it
is left in place because dropping a column alters a table, which would make the migration
destructive and therefore unapplicable until Milestone 13.

`LSUB`'s name set is the subscription list, so a subscribed name whose mailbox is gone is still
reported — flagged `\Noselect`, which is what §7.2.2 defines the attribute to mean: "It is not
possible to use this name as a selectable mailbox." `SUBSCRIBE` validates that the name exists,
which §6.3.6 explicitly permits; `UNSUBSCRIBE` must not, or a user could never stop following a
deleted mailbox.

### UIDVALIDITY is issued from a high-water mark

§6.3.3 requires a mailbox created with a deleted mailbox's name to use UIDs greater than the
previous incarnation's, **unless** its UIDVALIDITY differs. This server takes the exception
rather than preserving a UID counter per deleted name — so the value must genuinely differ every
time.

A value derived from surviving folders cannot promise that: the deleted folder's UIDVALIDITY
leaves with its row, so a delete and an immediate recreate would reissue the same number with
UIDs restarting at 1, and a client would serve cached mail under UIDs that now name different
messages. Migration 0012 therefore adds `MailboxUidValidity`, a per-mailbox high-water mark that
outlives the folder, and every issued value is `max(clock, high-water + 1)`.

## COPY and MOVE

`COPY` duplicates messages into another folder; `MOVE` (RFC 6851) does the same and removes the
originals. One repository method serves both, because §3.3 defines the second in terms of the
first — a move "has the same effect for each message as this sequence: 1. [UID] COPY 2. [UID]
STORE +FLAGS.SILENT `\DELETED` 3. UID EXPUNGE" — and then forbids the middle step's traces:
"response codes for a STORE MUST NOT be generated and the `\DELETED` flag MUST NOT be set for
any message." So a move deletes; it never flags.

**A missing destination earns `[TRYCREATE]`, and that is a MUST.** RFC 3501 §6.4.7: "Unless it is
certain that the destination mailbox can not be created, the server MUST send the response code
"[TRYCREATE]" as the prefix of the text of the tagged NO response." This is the only place the
code appears — `SELECT` deliberately does not use it, because a client cannot recover from
opening a missing folder by creating an empty one.

**The copy takes a new UID and keeps everything else.** §6.4.7: messages go "to the end of the
specified destination mailbox. The flags and internal date of the message(s) SHOULD be preserved,
and the Recent flag SHOULD be set, in the copy." Flags and date are preserved. `\Recent` is not
set, because this server never sets it anywhere and a copy is no place to start.

**The stored message is shared, not duplicated.** A copy is a second `Deliveries` row against the
same `Messages` row, which is what makes copying a large message cheap — and is the shape the
store-once-deliver-many schema was built for.

**Everything happens in one transaction**, which both RFCs demand in their own words. §6.4.7:
"If the COPY command is unsuccessful for any reason, server implementations MUST restore the
destination mailbox to its state before the COPY attempt." RFC 6851 §3.3 is stricter for a move:
"The server MUST leave each message in a state where it is in at least one of the source or
target mailboxes (no message can be lost or orphaned)." A half-done move is the one outcome that
loses mail.

`COPYUID` is not sent. RFC 6851 §4.3 asks for it only of "Servers supporting UIDPLUS", and this
server does not advertise UIDPLUS.

## APPEND

`APPEND mailbox [(flags)] [date-time] {literal}`. The two optional arguments are told apart by
shape rather than position — a flag list opens with `(` and a date-time with `"` — so all four
conformant forms reach the same parser.

**The literal is intercepted by the connection loop, not the command processor.** RFC 3501
§6.3.11's last argument is not on the command line, and this server's arrangement is that the
loop owns the stream while the processor owns the protocol. So the loop asks what the command
says, streams the octets itself, and comes back with what it stored.

**A synchronising literal gets a continuation first, and it must be flushed.** §4.3: the client
"MUST wait to receive a command continuation request […] before sending the octets of the
literal". A non-synchronising `{n+}` literal gets none — the client has already sent the octets,
so waiting for permission to receive what has arrived would deadlock.

**A literal is counted, never delimited.** §4.3: "The sequence of characters following the literal
is exactly the number of octets specified." A reader that stopped at a CRLF would truncate every
message containing a blank line — which is every message with a body.

**The octets stream straight into the message store.** A message may be tens of megabytes;
assembling it in memory to hand over afterwards would double that for nothing. The declared size
is checked before a byte is read, and the writer checks again as it fills, because a limit
checked in one place only stops being checked when a second caller appears.

**The destination is never created.** §6.3.11: "a server MUST return an error, and MUST NOT
automatically create the mailbox", with `[TRYCREATE]` a MUST in the same sentence. An untagged
`EXISTS` follows when the client has that mailbox selected, per the same section.

`\Recent` is not set, though §6.3.11 says "In either case, the Recent flag is also set". This
server never sets that flag anywhere, and setting it here alone would make `RECENT` report a
number no other command could produce.

The `Messages` row is written after the octets are committed, which the storage schema insists
on: a crash between the two leaves a file nobody references — which a sweep can remove — rather
than a row naming a file that does not exist. The row carries the digest the store computed, so
the schema's truncated-or-altered check works for an appended message as it does for a received
one.

## Known divergence: folder-name case depends on the database provider

**On SQLite folder names are matched exactly; on a default-collation SQL Server they are not.**
This server's design is exact matching — RFC 3501 §5.1 takes no position on non-`INBOX` names
("The interpretation of all other names is implementation-dependent") and this product chooses
the case-sensitive one of the three dispositions §5.1 lists, because a folder name is the user's
own text. That choice is true of SQLite, whose default `TEXT` collation is `BINARY`. It is not
true of SQL Server: `MailboxFolders.Path` is declared `NVARCHAR(512)` with no `COLLATE` clause,
so it inherits the database collation, and the common installation default is case-**in**sensitive.

Two observable consequences on SQL Server:

- `SELECT receipts` opens a folder called `Receipts`, where SQLite answers `NO`.
- `Receipts` and `receipts` cannot both exist, because `UX_MailboxFolders_Path` is unique and
  folds them together. The same pair is legal on SQLite, so a mailbox created there can fail to
  import.

**Not fixed here, deliberately.** The fix is `COLLATE Latin1_General_BIN2` on the column and its
unique index, which means altering an existing table — and this repository refuses to apply a
migration marked `@Destructive` until the backup subsystem lands in Milestone 13, while leaving
such a migration unmarked would misdescribe it. Tightening case-insensitive to case-sensitive
cannot lose rows (the existing unique index already forbade the colliding pairs), so the change
is safe whenever it is scheduled; it is a deployment decision rather than a code one. Recorded
here so the claim "this server matches folder names exactly" is not read as unconditional.

## STORE

Implemented for `FLAGS`, `+FLAGS` and `-FLAGS`, each with the optional `.SILENT` suffix — the
only data item RFC 3501 §6.4.6 defines for the command.

**The untagged `FETCH` responses report what was written, not what was asked for.** §6.4.6: "The
new value of the flags is returned as if a FETCH of those flags was done." The write reads the
result back inside the same transaction it wrote in, so the value reported is the value stored
rather than the value asked for — those differ whenever a flag was already set or could not be
stored at all. A message already in the requested state is skipped for the write and still
reported, because the response is the new value rather than a list of what changed.

§6.4.6 has a separate note that this server does **not** yet satisfy: "Regardless of whether or
not the `.SILENT` suffix was used, the server SHOULD send an untagged FETCH response if a change
to a message's flags from an external source is observed. The intent is that the status of the
flags is determinate without a race condition." Observing an external change needs a notification
path that does not exist until `IDLE` lands, so the SHOULD is unmet and recorded here rather than
claimed. The transaction above is a different guarantee and does not discharge it.

**`\Recent` survives every mode, including `FLAGS`.** §6.4.6 puts the exception inside the
sentence — "Replace the flags for the message (other than `\Recent`) with the argument" — and
§2.3.2 says the flag "can not be altered by the client". §9's `flag` production is annotated
"Does not include `\Recent`", so a client cannot even name it.

**The flag list may arrive without brackets, and an empty bracketed list means something.**
§9: `… SP (flag-list / (flag *(SP flag)))`, and `flag-list = "(" [flag *(SP flag)] ")"`. So
`STORE 1 +FLAGS \Deleted` is as conformant as `STORE 1 +FLAGS (\Deleted)`, and
`STORE 1 FLAGS ()` clears every flag — which is how a client marks a message unread, undeleted
and unflagged in one command.

**A flag this server cannot store is ignored rather than refused.** §7.1 sanctions it in as many
words: "If the client attempts to STORE a flag that is not in the PERMANENTFLAGS list, the server
will either ignore the change or store the state change for the remainder of the current session
only." The untagged `FETCH` then shows the client exactly what it got. Refusing would be within
the letter of §6.4.6's "NO - store error" and would break real clients — Thunderbird and Apple
Mail both send keywords like `$Junk` and `$MDNSent` without asking.

**A mailbox opened with `EXAMINE` refuses the command.** §6.3.2: "No changes to the permanent
state of the mailbox, including per-user state, are permitted." The client has already been told
twice, by `[PERMANENTFLAGS ()]` and a `[READ-ONLY]` completion, so this is a tagged `NO` rather
than a silently discarded write.

The write batches its UIDs at 500 per statement. Every UID is a bound parameter and both
providers cap those — SQLite historically at 999, SQL Server at 2,100 — so a store over a larger
set becomes more statements inside the one transaction rather than a driver error.

## EXPUNGE and CLOSE

`EXPUNGE` removes every message carrying `\Deleted` and sends one untagged `* n EXPUNGE` per
message removed, per RFC 3501 §6.4.3.

**The responses go out highest position first.** §7.4.1 makes sequence numbers renumber as
messages go — "The message sequence number for each successive message in the mailbox is
immediately decremented by 1, and this decrement is reflected in message sequence numbers in
subsequent responses" — and names both directions as legal: a "lower to higher" server and a
"higher to lower" one. Descending is the half where no number moves before it is sent, because
only higher positions have gone. So the numbers emitted are simply the positions as they stood
before the removal, and there is no running decrement anywhere in the product. In the one
response where an off-by-one makes a client delete the wrong mail, having no arithmetic at all is
worth more than the symmetry. §6.4.3's own example (messages 3, 4, 7, 11 of 11, answered
`3 3 5 8` by an ascending server) is reproduced as a test in both forms, to prove the descending
output names the same messages.

**No `EXISTS` follows.** §7.4.1: "The EXPUNGE response also decrements the number of messages in
the mailbox; it is not necessary to send an EXISTS response with the new value."

**`CLOSE` does the same removal and says nothing about it**, then returns to the authenticated
state — §6.4.2: "No untagged EXPUNGE responses are sent." That silence is the command's purpose;
the RFC explains that a `CLOSE-LOGOUT` sequence "is considerably faster than an `EXPUNGE-LOGOUT`
… because no untagged EXPUNGE responses (which the client would probably ignore) are sent."

**On a read-only mailbox the two commands differ, and the difference is the RFC's.** `EXPUNGE`
is refused with a tagged `NO` — §6.3.2 permits no change to the permanent state, and §6.4.3's
result list has the case for it. `CLOSE` succeeds, removes nothing and still deselects, because
§6.4.2 says so outright: "No messages are removed, and no error is given, if the mailbox is
selected by an EXAMINE command or is otherwise selected read-only." `CLOSE` has no `NO` result at
all. A server that refused there would fail every client that closes each mailbox it opens.

**Only the delivery goes; the stored message stays.** Expunging deletes the `Deliveries` row and
leaves the `Messages` row and its content file, which is what the schema intends — its own
comment on `ContentRemovedUtc` reads "The row outlives the file so that delivery history survives
retention, which is what an abuse investigation actually needs months later". Reclaiming a
content file once no delivery references it is a retention sweep's job and **no such sweep exists
yet**, so an expunged message's bytes stay on disk until one is built. Deleting them here would
destroy exactly what the schema keeps them for.

## IDLE

Held with a server-side timer that emits a keep-alive before the 29-minute RFC 2177 limit, and
cancelled cleanly on shutdown.

## POP3

Implemented for legacy device compatibility, **disabled by default**.

POP3's destructive-read model interacts badly with IMAP on the same mailbox: a POP3 client
that downloads and deletes removes mail the IMAP client expected to still be there. The admin
UI warns about this at the point of enabling it, not in a footnote.
