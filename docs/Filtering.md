# Filtering

> **Status: built and tested — Milestone 12.** The anti-spam pipeline, the attachment policy,
> the malware seam, the quarantine and the inbound rate limits are implemented, wired into the
> delivery path, and covered by tests. The exit criterion — a quarantine round trip — passes
> against a real database and a real delivery.
>
> **Two things to know.** The filter has **never been run against live mail**: every check is
> exercised against this product's own tests, the same caveat `docs/Standards.md` records for
> the authentication work. And the **Quarantine page is written but unrun** — it is a WPF
> binary, so it builds on Linux CI and can only be opened on Windows. `docs/Verification.md` is
> the checklist.

## What this product does not do

**It ships no word list and no trained model.** There is no corpus behind this project to have
built either from, and one invented from intuition would encode its author's idea of what spam
says — which is how a filter ends up junking a hospital's mail because of what it is about.
Every check here is about the *shape* of a message, its authentication, or what it carries.

**It ships no malware engine.** A bundled scanner is a signature database this project would
have to keep current forever, and a stale one is worse than none: it produces the reassurance of
a scan without the protection. What ships is the seam — `IMalwareScanner`. Point it at ClamAV,
at a Defender command line, or at whatever the organisation already licenses.

**It does not reject mail by default, and turning that on is deliberate.** See *The three
thresholds* below.

**It does not learn.** Nothing here adapts to what an operator releases or discards. A feedback
loop is a good feature and a bad one to build without the corpus to validate it against.

## The three actions, and why they are not equally reversible

| Action | What happens | Who can undo it |
|---|---|---|
| **Junk** | Delivered to the recipient's `\Junk` folder | The recipient, immediately |
| **Quarantine** | Held. Delivered to nobody, nobody notified | An operator, from the Quarantine page |
| **Reject** | Refused at SMTP time. Nothing is kept | Nobody |

**Junk is the right answer for "probably spam".** The recipient still has it, can still find it,
and can still tell the operator it was wrong. None of that is true of anything stronger.

**Quarantine is for what should not reach a recipient even in a junk folder** — malware, an
executable attachment — but which a human should be able to look at and release.

**The recipient is never notified of a hold.** A notification is how a quarantine becomes a
delivery channel for the very content it is holding back. The *sender* is told the message was
accepted, because telling them it was held confirms the address exists and tells them exactly
which attachment to rename.

**Rejection is off by default and has to be turned on.** `RejectThreshold` defaults to infinity,
so no weight tuning reaches it. Heuristic scoring is wrong often enough that a server which
discards mail on it will eventually discard something that mattered — and nobody will know,
because a rejection leaves nothing to find. An operator who wants that trade can have it; they
should have to ask.

## How a message is judged

Every check returns **signals**, and the policy turns their sum into an action. A signal is a
name, a score and a detail. Scores are additive and signed: a check that finds evidence of
legitimacy contributes a negative one, because the alternative — a separate "good" list weighed
against the bad one — makes every threshold two numbers instead of one.

**A signal describes and never quotes.** A verdict is readable under `ViewServerState`; the
message it is about needs `ReadMessageContent`. A signal carrying a subject line or a fragment
of the body would be a way to read mail with the weaker of the two permissions. `FilterSignal`
is where that rule lives and `docs/Security.md` is why.

### The checks

**Authentication** weighs what SPF, DKIM and DMARC already concluded — nothing is re-verified,
because `LocalDeliveryService` did it before the filter ran and a second pass would disagree
with the first the moment a key rotated between them.

These are the only signals in the product with real evidence behind them, which is why they
carry the heaviest weights *in both directions*. A DMARC pass is the strongest available
statement that a message is what it says it is, and a filter that could not lower a score would
junk legitimate mail every time a heuristic misfired.

A **temporary** DNS error scores nothing at all. It is a fact about this server's resolver, not
about the sender, and scoring it would make a local outage look like a spam wave while quietly
junking the mail of whoever sent during it.

A DMARC failure against a domain publishing `p=quarantine` is weighted at exactly the junk
threshold, on purpose: RFC 7489 §6.3 is the domain owner asking for that treatment, and they are
the authority on their own mail. `p=reject` never reaches the filter — `LocalDeliveryService`
refuses it first.

**Headers** checks structure: a missing `Date` or `Message-ID`, a message addressed to nobody, a
`Date` far enough out to be a sorting trick. Two `From` headers is weighted heavily because it
is an attack rather than sloppiness — clients differ on which they display, so a signature that
authenticates one can be shown under the other.

The shouting-subject check counts *cased letters* rather than testing for an absence of
lower-case ones. Most of the world's writing systems have no case, and the naive test fires on
every message written in Chinese, Arabic, Hebrew, Japanese or Korean — a filter that scored mail
for the alphabet it was written in.

**Attachments** is the cheapest real protection here, and it is not a malware scanner. It knows
nothing about what is inside a file. What it knows is that a Windows desktop will execute some
of these on a double-click and that no correspondent has a legitimate reason to send one, which
catches the whole category regardless of payload.

**The filename decides, never the declared type.** A sender picks both, so `Content-Type:
text/plain` on `invoice.exe` is a claim by the party that chose the payload.

**Every encoding a client honours is decoded first**, or the policy is decorative: a check that
read `filename` literally is defeated by writing `filename*=utf-8''payload%2Eexe` instead. RFC
2231 extended parameters, RFC 2231 continuations in section order, and RFC 2047 encoded-words —
which §5 forbids in a parameter and senders write anyway — are all understood, and the forms are
preferred in the order a client prefers them.

Trailing dots and spaces are stripped, because Win32 strips them and `payload.exe. ` is the same
file to the recipient's desktop. A right-to-left override in a name is the finding in itself:
there is no legitimate use of a character that makes `CV[U+202E]fdp.exe` render as `CVexe.pdf`.

**Archives are deliberately not blocked.** Blocking them breaks ordinary business mail, and
unpacking one to look inside is a decompression-bomb target for no gain. That is a scanner's job.

**Malware** hands the message to whatever engine is configured, and reports `NotScanned` rather
than `Clean` when there is none. The distinction is the whole point: a dashboard that rendered
"no scanner configured" as "clean" would tell an operator their mail was being checked when
nothing was checking it.

An engine that cannot answer is not a clean message either. `FailClosedOnScannerError` decides
what happens, and it is **off**: a mail server that stops delivering because an optional
component went down is the worse surprise.

**Block lists** consult the same `IReputationProvider` the readiness report uses, and that
matters — its implementation caches and rate-limits, because most of these lists are run by
volunteers and a busy MTA querying one naïvely gets cut off. That presents as *every* address
appearing listed, which would turn this check into one that junks all mail. A list reporting
anything other than healthy contributes nothing.

One listing is weighted below the junk threshold: it is somebody else's opinion, reached by
criteria this server cannot see and cannot appeal, and it is wrong often enough — a shared NAT,
a recycled address, a stale entry — that mail should not be destroyed on it alone. Two
independent lists agreeing is a different matter, and two of them add up to one.

This check is **off by default**, separately from whether `Deliverability:BlockLists` is
populated, because the report's handful of queries an operator asked for is a different
proposition from one query per inbound message.

### What is not scored

Malware and a blocked attachment set a **floor** on the action rather than pushing a number up.
Expressing them as a large weight would work until somebody tuned a threshold, and then it would
silently stop working.

## Bounds, and why the concurrent case is the one that matters

The pipeline reads a message whole, because `ImapMimeTree.Parse` needs the octets contiguous and
a streaming MIME parser would be a second implementation of a structure IMAP already has one of.
`ImapCommandProcessor` makes the same departure from `IMessageStore`'s "nothing needs the whole
message resident", and `docs/IMAP.md` records what it costs there.

**What is different here is who is asking.** IMAP reads a message because an authenticated user
asked for that message. The filter reads every message a stranger delivers. So 32 MB per message
is not a bound by itself — a hundred concurrent connections each just under it is three
gigabytes, and every one of those connections is free for anyone who can reach port 25. A
semaphore caps how many can be resident at once, held across the parse rather than just the read
because the MIME tree references the same buffer.

**It queues rather than sheds.** A message that waited is delayed; a message that skipped the
filter is unfiltered mail delivered because the server was busy, which is a bypass anyone can
trigger by being busy at it.

**A message too large to examine is reported, never passed.** Otherwise "send it big" is the
bypass nobody has to be clever to find. It still gets its headers and its authentication results
weighed, and the checks that needed a body say they did not see one.

## Failing open

A check that throws is dropped with a warning and the rest run. A pipeline that throws returns a
clean verdict. A filter whose own bug stops mail flowing is a worse failure than the spam it
would have caught — and an operator is far more likely to notice mail that arrived wrongly than
mail that never arrived at all. This is the same posture the DKIM/DMARC step above it takes.

## The quarantine

**The content is not copied.** The message is already in the store and the `Messages` row
already names it; the quarantine row carries the verdict and the state, and a release reads the
same file an ordinary delivery would have.

**A held message keeps its recipient rows.** They are the record of who it was for and the only
thing a release has to deliver against. **The recipients never come from the headers** — a
released message's `To:` line is whatever the sender chose to put there, and delivering to it
would let a held message name its own audience. This is one of the few places where "an
administrator asked for it" is not a sufficient reason.

**Releasing takes the same code path an ordinary delivery takes**: the same alias expansion, the
same UID allocation, the same quota accounting. A release that wrote its own delivery rows would
be a second implementation of the thing that puts mail in mailboxes, and the bug it eventually
grew would only ever show up in released mail.

**Released mail goes to the INBOX, never to Junk.** An operator has looked at it and decided it
is legitimate; putting it where the recipient may never look would make the release a gesture.

**Resolution is a conditional update, not a read followed by a write.** Two administrators
looking at the same quarantine is the ordinary case: whoever clicks second is told it was
already handled rather than delivering the message a second time. `WHERE Status = 0` and the
affected-row count make that a fact about the database rather than a hope about timing, and the
claim is taken *before* the delivery.

**Releasing needs `ReadMessageContent`; discarding needs `ManageSecurity`.** The asymmetry is
the safe direction: refusing to deliver a message the filter already refused to deliver changes
nothing about who can read mail, whereas releasing one does — and the honest way to decide that
is to have read it.

**Resolving does not remove the row.** "Did we release that, and who decided?" has an answer six
months later, and it outlives the message being expunged from the mailbox it was released into.
Discarding removes the bytes and keeps the record.

**Retention is fixed onto each row when the message is held**, so shortening the setting does
not retroactively expire what is already held.

## Rate limits

`SmtpConnectionLimiter` bounds how many connections one peer holds **at once**. It says nothing
about how fast a peer opens them, or what a peer does inside a connection it legitimately holds.
Both are free to the sender and expensive here.

### Across connections

`InboundRateLimiter` bounds connections and messages per address per hour. A peer that connects,
delivers, disconnects and repeats never exceeds a concurrency cap however fast it goes — the
shape of most junk delivery and of the cheapest denial of service against a mail server.

**What is counted, and against whom:**

- **Connections** are counted on every SMTP listener, submission included, because an address
  past its allowance is past it whichever port it knocks on, and they are counted at accept,
  before anything is known about them. **A connection that signs in is given back**: it has shown
  it is not the flood the allowance exists to stop. So an office whose staff all submit through
  one NAT address never spends it, while connections that never sign in — which is what a
  password-guessing run is made of — spend it exactly as before. A refused connection gets a 421
  before any command is read.
- **Messages** are counted when a transaction starts, at `MAIL FROM`, whether or not a message
  is then accepted — Postfix's convention, and the only point at which the refusal arrives
  before the body has crossed the wire. Only sessions that have **not** signed in are counted.
  A signed-in session is charged to its mailbox's `MaxMessagesPerMailboxPerHour` instead, so
  every transaction draws on exactly one allowance and colleagues behind one address do not
  spend each other's. Past the allowance, `MAIL FROM` is answered
  `421 4.7.0 Not accepting more mail from this address for now; try again later` and the
  connection is closed: every further transaction in the window would be refused the same way.

Until the testing pass after Milestone 12, the message allowance was configurable, documented and
unit-tested, and nothing on the SMTP path consulted it. `SmtpWireTests` now drives it through a
real listener, because the limiter was never the broken part — the wiring to it was.

**Counted in memory, not in the database.** A row written per inbound connection would make the
limiter an amplifier for the attack it exists to stop. The counts are per process and reset on
restart, which is the right trade: the limit exists to make a flood expensive, not to keep a
ledger.

**Its own table is bounded, and that is not a detail.** A limiter keyed by source address with
no cap on how many addresses it remembers is a memory-exhaustion vector reachable by anyone with
a botnet — the defence becoming the vulnerability. At the cap it **admits** rather than refuses:
an over-full table means this server has lost track, and refusing mail on the strength of a fact
it does not have would turn a flood from one set of addresses into an outage for everybody else.

A **fixed** window rather than a sliding one, because a sliding window needs a timestamp per
event and an address at its limit would cost memory proportional to the limit. A peer can send
two windows' worth across a boundary; against limits set this far above legitimate traffic, that
is not the case worth paying for.

### Within a connection

`SmtpAbusePolicy` closes a session that has stopped being a mail delivery. RFC 5321 §4.3.2
explicitly contemplates this.

| Counter | Default | What it is for |
|---|---|---|
| Refused commands | 20 | A client that is not speaking SMTP |
| Refused recipients | 25 | A directory harvest |

**The counters are not cleared by any reset.** They are this server's own accounting rather than
knowledge obtained from the client, so `RSET` does not buy another round — the same rule
`FailedAuthenticationAttempts` has followed since Milestone 7.

Failed `AUTH` attempts are deliberately **not** in this policy: the command processor already
bounds them with `MaxAuthenticationAttempts`, and a second limit on one fact is a second number
to keep in step, with the wrong one silently winning whenever they disagree.

**The 421 says the same vague thing whichever limit fired.** A harvester who learns how many
guesses they get per connection knows exactly how to pace around the limit.

**Nothing bans an address.** Dropping the connection costs the peer a reconnection and costs
this server nothing, and it cannot be turned into a denial of service against a third party by
anybody able to spoof a source address.

## Configuration

```jsonc
"Filtering": {
  "Enabled": true,
  "JunkThreshold": 5.0,
  "QuarantineThreshold": 10.0,
  "RejectThreshold": 0,          // 0 or negative means never. See above.
  "QuarantineRetentionDays": 30,
  "UseBlockLists": false,        // one DNS query per inbound message when on
  "FailClosedOnScannerError": false
},
"Limits": {
  "MaxInboundConnectionsPerHour": 120,   // per address, across every listener; sign-ins given back
  "MaxInboundMessagesPerHour": 600       // per address, transactions not signed in
}
```

The thresholds are conventional rather than derived — this product has no corpus to have tuned
them against, and saying so is more useful than implying otherwise. Five is roughly "two
independent checks both think so".

## What an operator actually does

1. **Read the Quarantine page** (under Mail) when something is held. The reasons are the page;
   the score is a column.
2. **Release what the filter got wrong.** That is what the quarantine is for.
3. **Turn on a malware scanner** if the organisation has one. The seam is `IMalwareScanner`.
4. **Leave `RejectThreshold` alone** unless there is a specific reason not to.
