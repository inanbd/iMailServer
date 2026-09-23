# Verification — the runs this server has not had

> **Status: a checklist, not a result.** Nothing in this document has been carried out. It exists
> so that the two milestone exit criteria waiting on a Windows host can be worked through
> mechanically rather than explored, and so that a failure is recorded as a finding rather than
> remembered as an impression.

Milestones 10 and 11 are built and tested, and neither has been exercised against anything real.
`docs/Standards.md` is careful about the difference throughout; this is the list of what would
close it.

Everything below needs a Windows host, because `MailServer.Admin` targets `net10.0-windows` and
`Directory.Build.props` is explicit that `EnableWindowsTargeting` makes the projects *compile*
off Windows without making the binaries *run* there.

---

## What to set up once

Both milestones need the same environment, so it is worth building once.

| Needs | Why |
|---|---|
| A Windows Server host with a **static public IP** | Reputation and PTR both attach to the address |
| **PTR control** for that address | `IdentityChecks` scores forward-confirmed reverse DNS, and major receivers reject mail without it |
| A domain with **DNS you can edit** | Every record the wizard proposes has to actually go somewhere |
| A **publicly trusted certificate** for the mail hostname | A self-signed certificate fails the TLS category by design, and IMAP clients will refuse it |
| **Inbound and outbound TCP 25** | See the README's warning: most cloud providers block outbound 25 by default |
| A mailbox at **Gmail or Microsoft 365** that you own | The delivery test's whole value is the receiver's own verdict |

Run the DNS wizard **first** and publish what it proposes. Several checks below are meaningless
until the records exist, and the wizard is faster than writing them by hand.

---

## Milestone 10 — IMAP and POP3 against real clients

**Exit criterion (`docs/Architecture.md` §27):** *Thunderbird/Outlook/Apple Mail interoperate
without mail loss.*

**What this is really testing** is UID semantics. `docs/IMAP.md` opens by saying why: a server
that gets UIDs wrong makes clients silently re-download mail or **delete it**, the failure
happens on the client, and it destroys trust permanently. Everything below is arranged around
catching that rather than around covering commands.

### Before connecting a client

Enable the listeners — both are **off by default** (`MailServer:Imap:ImplicitTls:Enabled`).
Port 993 is the one to use. Check the greeting and capability line first with a raw TLS client,
because a wrong capability list sends every subsequent test down the wrong path:

- [ ] `CAPABILITY` advertises `IMAP4rev1 LITERAL- CHILDREN IDLE NAMESPACE UNSELECT MOVE`
- [ ] It advertises **`LITERAL-` and never `LITERAL+`** — RFC 7888 §5 forbids both at once, and
      this server caps non-synchronising literals at 4096 octets
- [ ] Before login on port 143, it advertises `LOGINDISABLED` and refuses `LOGIN`

### Per client — Thunderbird, Outlook, Apple Mail

Run all of it for each, in this order. The order matters: several steps set up the state the
later ones check.

1. **Initial sync.** Add the account, let it download a mailbox with at least a few hundred
   messages across several folders.
   - [ ] Every folder appears, with the special-use ones (`Sent`, `Drafts`, `Trash`, `Junk`,
         `Archive`) recognised as such rather than duplicated — RFC 6154 attributes are emitted
         on plain `LIST`
   - [ ] Message counts match what the server reports
   - [ ] **No folder is created that already existed** under a different name (a client creating
         `Sent Items` beside `Sent` means the special-use attributes were not read)

2. **A non-ASCII folder name.** Create `Späm` or `テスト` from the client.
   - [ ] It round-trips: created, listed, selected, and still correct after a reconnect
   - This is the single highest-value step. It exercises modified UTF-7 **and** the literal path
         added in this milestone, and it is the first thing a real client does that the old
         code could not handle.

3. **`SEARCH` with 8-bit text.** Search for a non-ASCII word.
   - [ ] Results are correct rather than confidently empty — a `SEARCH` term arriving as a
         literal used to be parsed as the specifier's own text

4. **IDLE push.** Leave the client open on the inbox. Deliver a message from outside.
   - [ ] It appears **without the client polling** (watch for an untagged `EXISTS`)
   - [ ] Change a flag from a *second* client and confirm the first sees it — §6.4.6's
         last-paragraph SHOULD, served by `ImapFlagWatch`

5. **Flags, across two clients.** Read, unread, flagged, answered.
   - [ ] Both clients converge on the same state

6. **Move and copy.** Move a message between folders, then copy one.
   - [ ] The message arrives once and leaves once
   - [ ] **No `\Deleted` flag is set by a `MOVE`** — RFC 6851 §3.3 forbids it

7. **Append from Sent.** Send a message from the client so it files a copy.
   - [ ] The copy appears in `Sent` with the right flags and internal date

8. **Expunge.** Delete messages and expunge.
   - [ ] The client renumbers correctly and shows no ghosts
   - [ ] Other sessions do not lose their place

9. **Offline and reconnect.** Take the client offline, change mail server-side, reconnect.
   - [ ] It reconciles without re-downloading everything (a full re-download means `UIDVALIDITY`
         moved when it should not have)

10. **The mail-loss check, at the end of each client.** Compare the server's message count and
    UIDs against what the client holds.
    - [ ] Nothing is missing on either side
    - [ ] No message was silently duplicated

### Where mail loss hides

Watch for these specifically; each is quiet:

- **`UIDVALIDITY` changing when it should not.** Every client discards its cache and
  re-downloads. It looks like slowness, not like a bug.
- **Sequence numbers renumbering before the client was told.** `docs/IMAP.md` records that
  untagged `EXPUNGE` is never sent from a poll for exactly this reason.
- **A client deleting mail it should have kept.** The worst outcome and the reason this criterion
  exists. If it happens, capture the client's protocol log before anything else.

### POP3

Only if you intend to enable it — it is **off by default and should stay off** where IMAP will
do, because a destructive read removes mail an IMAP client can still see.

- [ ] Port 995 works; port 110 refuses `USER`/`PASS` until `STLS`
- [ ] A dropped connection before `QUIT` deletes nothing — RFC 1939 §6 makes that a MUST

---

## Milestone 11 — the readiness report

**Exit criterion:** *Full readiness report renders with evidence for every check.*

The page is built and has **never been rendered**, so treat the first run as a smoke test of the
UI before treating it as a report about the server.

1. **It renders.** Open Deliverability → Readiness, type the domain, run the report.
   - [ ] The page draws without a binding error
   - [ ] The verdict appears **above** the score, and the score appears as a per-category
         breakdown rather than only a number

2. **Evidence is present for every check.** Select several checks, including passing ones.
   - [ ] Expected, Found, Source and TTL are populated where the check made a lookup
   - [ ] A remedy is shown for everything not passing
   - [ ] **No check shows a verdict with an empty evidence panel** — that is the criterion, and
         an empty panel means the check is not reporting what it saw

3. **Inconclusive is not hiding.** If any check could not reach an answer, it must appear in
   *Needs attention* rather than among the passes. A resolver timeout reported as a pass is the
   one mistake this report must not make.

4. **The DNS wizard.** Build a plan; publish what it proposes; re-run the report.
   - [ ] Checks that were failing for missing records now pass
   - [ ] The zone text pastes into your DNS provider without hand-editing

5. **The delivery test.** Send to the Gmail or Microsoft 365 mailbox you own.
   - [ ] It is accepted
   - [ ] The transcript shows the conversation and **contains no message content**
   - [ ] Open the delivered message and read the authentication results the provider recorded.
         **That verdict is the real result of this milestone** — SPF, DKIM and DMARC should all
         pass. It is the receiver's own judgement and it is worth more than every local check.

6. **TLS report collection, if you publish a `_smtp._tls` record.** Point
   `MailServer:Deliverability:TlsRpt:ReportMailbox` at the address in that record and enable
   collection. Reports are daily and aggregate, so this is the one step with a wait in it.
   - [ ] A day or two after publishing, a report from Google or Microsoft appears in that mailbox
   - [ ] It is collected, and appears on **Deliverability → TLS Reports** for that domain, with
         the selected report's failures and remedies beside the grid
   - [ ] Before anything is collected, that page explains why the list is empty rather than
         showing a bare grid
   - [ ] Pasting a report's JSON into *Analyse a report* shows the same analysis
   - [ ] The mailbox is **unchanged** — nothing marked, moved or deleted by the collector
   - [ ] A non-report in the same mailbox (a bounce, a note) is not re-opened on the next pass

7. **MTA-STS, only if you publish a policy.** It is off by default for good reason: RFC 8461
   §8.3's `enforce` mode with a wrong `mx` list makes senders **refuse to deliver**, and they
   keep refusing for `max_age` because they cached it.
   - [ ] Start in `testing` mode
   - [ ] `https://mta-sts.<domain>/.well-known/mta-sts.txt` serves the policy as `text/plain`
         over a trusted certificate
   - [ ] The `_mta-sts` TXT record's `id` matches the served policy's
   - [ ] Leave it in `testing` until TLS reports are quiet — then consider `enforce`

---

## What these runs cannot close

Two things stay open regardless of how the above goes, and should not be read as passing because
the checklist did:

- **Whether senders actually deliver TLS reports here.** Collection is built and tested, but no
  real sender has ever delivered a report to this server. Publishing the `_smtp._tls` record and
  waiting a day or two for Google to send one is the only way to find out, and it is worth doing
  while you have the environment up. See `docs/Deliverability.md`.
- **The folder-name case divergence.** `docs/IMAP.md` records that folder names match exactly on
  SQLite and case-insensitively on a default-collation SQL Server. If you run SQL Server, step
  2 above may behave differently from the same test on SQLite, and that is the known reason.

---

## Recording the result

Whatever happens, write it down here rather than in a commit message. `docs/Standards.md`'s rule
is that nothing is marked Implemented without evidence, and "we tried it and it seemed fine" is
not evidence a later reader can check. For each client: version, date, and either *passed* or
the specific step that failed with the client's protocol log attached.

---

## Milestone 12 — the filter, against live mail

Everything below needs a server taking real inbound mail. None of it can be done from this
repository's CI, and none of it is claimed in `docs/Filtering.md`.

1. **The Quarantine page renders.** Open Mail → Quarantine on Windows. It is a WPF binary and
   has never been run. Check that a held message lists its reasons, that Release and Discard are
   enabled only for a held one, that **Refresh** reloads the list (it was bound to a command that
   did not exist until the post-Milestone-12 testing pass), and that the grid survives an empty
   quarantine.

2. **A held message releases into a real mailbox.** Send yourself a message with a `.exe`
   attachment from an outside account. It should be held, the sender should see a 250, and
   nobody should receive it. Release it and confirm it lands in the INBOX rather than Junk.

3. **The thresholds are not junking real mail.** Run for a week with `RejectThreshold` at its
   default and read what lands in `\Junk`. The numbers in `FilteringOptions` are conventional,
   not tuned — this is the exercise that would tune them.

4. **A malware scanner is wired in.** `IMalwareScanner` has one implementation and it reports
   `NotScanned`. Point it at ClamAV and confirm an EICAR test file is held, and that stopping
   the daemon does not stop mail (with `FailClosedOnScannerError` off) and does hold mail (with
   it on).

5. **The rate limits do not trip a real exchanger.** Watch for 421s in the log against Gmail or
   Microsoft 365 delivering a backlog. `MaxInboundConnectionsPerHour` is set from what those
   providers are believed to do, not from what they were observed doing here. Mail clients that
   sign in are given their connection back, so an office behind one address should never see
   one; if it does, that is a bug, not a limit to raise.

6. **A domain's first day, in the console.** On the Domains page, create a domain **without** a
   mail hostname.
   - [ ] Enable is refused, and the error says the hostname is missing
   - [ ] The **Mail hostname** box sets it, and the domain's quota and message size are unchanged
   - [ ] Mail sent to the domain while it is Pending gets `450 4.3.2` and arrives once it is
         enabled, rather than bouncing

