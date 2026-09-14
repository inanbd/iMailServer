-- =============================================================================
-- AetherMail Server - message storage and local delivery (SQLite)
-- Milestone 6
--
-- Purely additive: three new tables and their indexes. No existing table is
-- altered and no data is rewritten, so this carries no destructive directive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- Messages: one row per message this server has accepted, whatever its fate.
--
-- The CONTENT IS NOT HERE. It is a file under Storage:DataRoot/Messages, named by
-- this row's Id. A mail store is mostly large opaque blobs written once and read
-- whole, which is the workload a relational database is worst at; keeping them out
-- means a backup, a restore or a provider migration of the metadata moves
-- kilobytes rather than gigabytes.
--
-- The row is written AFTER the file is committed. A crash between the two leaves a
-- file nobody references, which the sweep removes - never a row naming a file that
-- does not exist, which is a mailbox the owner cannot open.
-- -----------------------------------------------------------------------------
CREATE TABLE Messages (
    Id                TEXT    NOT NULL PRIMARY KEY,

    -- Size and hash of the stored file, recorded at commit. Together they detect a
    -- file that has been truncated or altered underneath the row that names it,
    -- which is the difference between noticing corruption and serving it.
    SizeBytes         INTEGER NOT NULL,
    ContentSha256     TEXT    NOT NULL,

    -- The envelope, as it was on the wire. Deliberately NOT the From: and To:
    -- headers: those are message content and a sender writes whatever it likes in
    -- them. Every later decision - bounces, DMARC alignment, abuse investigation -
    -- needs the envelope, and by then the headers are no substitute.
    --
    -- NULL ReversePath is the null reverse-path <>, which is a real and meaningful
    -- sender: it is what a bounce uses, precisely so a bounce cannot itself bounce.
    ReversePath       TEXT    NULL,

    -- What the peer claimed in EHLO, and what the transport actually observed. The
    -- claim is kept because it is evidence, not because it is true.
    RemoteAddress     TEXT    NOT NULL,
    GreetedName       TEXT    NULL,

    -- 0 InboundMta, 1 Submission, 2 ImplicitTlsSubmission. Which listener accepted
    -- it, so an audit can tell mail from the Internet from mail a customer sent.
    ListenerRole      INTEGER NOT NULL,

    TlsActive         INTEGER NOT NULL DEFAULT 0,
    AuthenticatedAs   TEXT    NULL,

    ReceivedUtc       TEXT    NOT NULL,

    -- Set when the content file is removed. The row outlives the file so that
    -- delivery history survives retention, which is what an abuse investigation
    -- actually needs months later.
    ContentRemovedUtc TEXT    NULL
) STRICT;

-- Delivery and retention both sweep by arrival time.
CREATE INDEX IX_Messages_ReceivedUtc ON Messages (ReceivedUtc);

-- Finds every message still holding a content file, for the retention sweep.
CREATE INDEX IX_Messages_Retained ON Messages (ReceivedUtc) WHERE ContentRemovedUtc IS NULL;

-- Duplicate detection and integrity checks both start from the hash.
CREATE INDEX IX_Messages_ContentSha256 ON Messages (ContentSha256);


-- -----------------------------------------------------------------------------
-- MessageRecipients: the envelope recipients, exactly as accepted.
--
-- One row per RCPT TO that earned a 250, with the relay decision recorded. That
-- decision is the single most consequential one this server makes, and writing it
-- down means "why did we relay this?" is answerable from the database months later
-- rather than from whatever the log retention happened to be.
--
-- Separate from Deliveries below because they are different things: a recipient is
-- what the sender asked for, a delivery is what actually happened to a mailbox
-- after aliases expanded. One recipient can produce several deliveries, or none.
-- -----------------------------------------------------------------------------
CREATE TABLE MessageRecipients (
    Id             TEXT    NOT NULL PRIMARY KEY,
    MessageId      TEXT    NOT NULL,

    -- The address as the sender wrote it, before alias expansion. Kept because a
    -- bounce has to name the address the sender used, not the mailbox it resolved
    -- to - a sender told "unknown-internal-account@example.com failed" cannot act
    -- on it, and it leaks the internal name.
    Address        TEXT    NOT NULL,

    -- RelayDecision: 1 AcceptLocal, 2 AcceptRelay. 0 (Deny) never appears: a denied
    -- recipient is refused at RCPT TO and never becomes a row.
    RelayDecision  INTEGER NOT NULL,

    CreatedUtc     TEXT    NOT NULL,

    CONSTRAINT FK_MessageRecipients_Message
        FOREIGN KEY (MessageId) REFERENCES Messages (Id) ON DELETE CASCADE,

    -- A denied recipient must be unrepresentable, not merely absent.
    CONSTRAINT CK_MessageRecipients_Decision CHECK (RelayDecision IN (1, 2))
) STRICT;

CREATE INDEX IX_MessageRecipients_MessageId ON MessageRecipients (MessageId);
CREATE INDEX IX_MessageRecipients_Address   ON MessageRecipients (Address);


-- -----------------------------------------------------------------------------
-- Deliveries: one row per (message, mailbox folder) pair.
--
-- This is the mailbox index IMAP reads. The Uid column is why the table exists in
-- this shape: IMAP promises that a UID names the same message for the life of a
-- folder's UIDVALIDITY, so it is assigned here, once, and never reassigned.
--
-- A message delivered to three mailboxes is ONE file and THREE rows. Storing three
-- copies would triple the disk for a message sent to a distribution list, and
-- would make deduplication a background job that has to prove two files are
-- identical rather than a property of the schema.
-- -----------------------------------------------------------------------------
CREATE TABLE Deliveries (
    Id              TEXT    NOT NULL PRIMARY KEY,
    MessageId       TEXT    NOT NULL,
    MailboxId       TEXT    NOT NULL,
    FolderId        TEXT    NOT NULL,

    -- Strictly increasing within the folder, assigned from MailboxFolders.NextUid.
    -- Never reused, never reordered: a client that cached UID 42 must still find
    -- the same message at UID 42 or the cache silently serves the wrong mail.
    Uid             INTEGER NOT NULL,

    -- IMAP system flags, as a bitmask. 1 Seen, 2 Answered, 4 Flagged, 8 Deleted,
    -- 16 Draft, 32 Recent.
    Flags           INTEGER NOT NULL DEFAULT 0,

    -- The envelope recipient this delivery came from, so an alias expansion can be
    -- traced back to the address the sender actually wrote.
    RecipientId     TEXT    NULL,

    -- IMAP INTERNALDATE. Distinct from the message's Date: header, which the sender
    -- wrote and may have got wrong by years.
    InternalDate    TEXT    NOT NULL,

    CreatedUtc      TEXT    NOT NULL,

    -- RESTRICT rather than CASCADE. Deleting a message row out from under a folder
    -- would leave IMAP clients with cached UIDs pointing at nothing and force a
    -- full resynchronisation; expunging is a deliberate operation, not a side
    -- effect of tidying the Messages table.
    CONSTRAINT FK_Deliveries_Message
        FOREIGN KEY (MessageId) REFERENCES Messages (Id) ON DELETE RESTRICT,

    CONSTRAINT FK_Deliveries_Mailbox
        FOREIGN KEY (MailboxId) REFERENCES Mailboxes (Id) ON DELETE RESTRICT,

    CONSTRAINT FK_Deliveries_Folder
        FOREIGN KEY (FolderId) REFERENCES MailboxFolders (Id) ON DELETE RESTRICT,

    CONSTRAINT FK_Deliveries_Recipient
        FOREIGN KEY (RecipientId) REFERENCES MessageRecipients (Id) ON DELETE SET NULL
) STRICT;

-- The UID uniqueness promise, enforced by the database rather than by whichever
-- code path happened to assign it.
CREATE UNIQUE INDEX UX_Deliveries_Folder_Uid ON Deliveries (FolderId, Uid);

-- The query IMAP runs constantly: everything in this folder, in UID order.
CREATE INDEX IX_Deliveries_Folder_Uid ON Deliveries (FolderId, Uid);

-- Quota recalculation and per-mailbox listing.
CREATE INDEX IX_Deliveries_MailboxId ON Deliveries (MailboxId);

-- Finds every delivery of one message, which is what an expunge has to check
-- before the content file can be removed.
CREATE INDEX IX_Deliveries_MessageId ON Deliveries (MessageId);

-- The same message must not be delivered to the same folder twice. Without this,
-- a retried delivery after a partial failure silently duplicates mail.
CREATE UNIQUE INDEX UX_Deliveries_Folder_Message ON Deliveries (FolderId, MessageId);
