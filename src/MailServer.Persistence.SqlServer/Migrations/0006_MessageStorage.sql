-- =============================================================================
-- AetherMail Server - message storage and local delivery (Microsoft SQL Server)
-- Milestone 6
--
-- The SQL Server counterpart of the SQLite 0006 script. The two are kept
-- deliberately in step; anything that cannot be expressed identically is called
-- out in a comment rather than allowed to diverge silently.
--
-- Purely additive: three new tables and their indexes. No existing table is
-- altered, so this carries no destructive directive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- Messages: one row per message this server has accepted, whatever its fate.
--
-- The CONTENT IS NOT HERE. It is a file under Storage:DataRoot/Messages, named by
-- this row's Id. A mail store is mostly large opaque blobs written once and read
-- whole, which is the workload a relational database is worst at; keeping them out
-- means a backup or a restore of the metadata moves kilobytes rather than
-- gigabytes.
--
-- The row is written AFTER the file is committed. A crash between the two leaves a
-- file nobody references, which the sweep removes - never a row naming a file that
-- does not exist, which is a mailbox the owner cannot open.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.Messages (
    Id                UNIQUEIDENTIFIER  NOT NULL,

    -- Size and hash of the stored file, recorded at commit. Together they detect a
    -- file truncated or altered underneath the row that names it, which is the
    -- difference between noticing corruption and serving it.
    SizeBytes         BIGINT            NOT NULL,
    ContentSha256     CHAR(64)          NOT NULL,

    -- The envelope, as it was on the wire. Deliberately NOT the From: and To:
    -- headers: those are message content and a sender writes whatever it likes in
    -- them. Bounces, DMARC alignment and abuse investigation all need the envelope.
    --
    -- NULL ReversePath is the null reverse-path <>, a real and meaningful sender:
    -- it is what a bounce uses, so a bounce cannot itself bounce.
    ReversePath       NVARCHAR(320)     NULL,

    -- What the peer claimed in EHLO, and what the transport actually observed. The
    -- claim is kept because it is evidence, not because it is true.
    RemoteAddress     NVARCHAR(45)      NOT NULL,
    GreetedName       NVARCHAR(255)     NULL,

    -- 0 InboundMta, 1 Submission, 2 ImplicitTlsSubmission.
    ListenerRole      INT               NOT NULL,

    TlsActive         BIT               NOT NULL CONSTRAINT DF_Messages_TlsActive DEFAULT (0),
    AuthenticatedAs   NVARCHAR(320)     NULL,

    ReceivedUtc       DATETIMEOFFSET(7) NOT NULL,

    -- Set when the content file is removed. The row outlives the file so delivery
    -- history survives retention, which is what an abuse investigation needs months
    -- later.
    ContentRemovedUtc DATETIMEOFFSET(7) NULL,

    CONSTRAINT PK_Messages PRIMARY KEY CLUSTERED (Id)
);
GO

CREATE INDEX IX_Messages_ReceivedUtc ON dbo.Messages (ReceivedUtc);
GO

-- Filtered index: the SQL Server spelling of SQLite's partial index, and the same
-- intent - find every message still holding a content file.
CREATE INDEX IX_Messages_Retained
    ON dbo.Messages (ReceivedUtc)
    WHERE ContentRemovedUtc IS NULL;
GO

CREATE INDEX IX_Messages_ContentSha256 ON dbo.Messages (ContentSha256);
GO


-- -----------------------------------------------------------------------------
-- MessageRecipients: the envelope recipients, exactly as accepted.
--
-- One row per RCPT TO that earned a 250, with the relay decision recorded. That
-- decision is the most consequential this server makes, and writing it down means
-- "why did we relay this?" is answerable from the database months later rather
-- than from whatever the log retention happened to be.
--
-- Separate from Deliveries because they are different things: a recipient is what
-- the sender asked for, a delivery is what happened to a mailbox after aliases
-- expanded. One recipient can produce several deliveries, or none.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.MessageRecipients (
    Id             UNIQUEIDENTIFIER  NOT NULL,
    MessageId      UNIQUEIDENTIFIER  NOT NULL,

    -- The address as the sender wrote it, before alias expansion. A bounce must
    -- name the address the sender used, not the mailbox it resolved to: the sender
    -- cannot act on an internal name, and printing one leaks it.
    Address        NVARCHAR(320)     NOT NULL,

    -- RelayDecision: 1 AcceptLocal, 2 AcceptRelay. 0 (Deny) never appears - a
    -- denied recipient is refused at RCPT TO and never becomes a row.
    RelayDecision  INT               NOT NULL,

    CreatedUtc     DATETIMEOFFSET(7) NOT NULL,

    CONSTRAINT PK_MessageRecipients PRIMARY KEY CLUSTERED (Id),

    CONSTRAINT FK_MessageRecipients_Message
        FOREIGN KEY (MessageId) REFERENCES dbo.Messages (Id) ON DELETE CASCADE,

    -- A denied recipient must be unrepresentable, not merely absent.
    CONSTRAINT CK_MessageRecipients_Decision CHECK (RelayDecision IN (1, 2))
);
GO

CREATE INDEX IX_MessageRecipients_MessageId ON dbo.MessageRecipients (MessageId);
GO

CREATE INDEX IX_MessageRecipients_Address ON dbo.MessageRecipients (Address);
GO


-- -----------------------------------------------------------------------------
-- Deliveries: one row per (message, mailbox folder) pair.
--
-- The mailbox index IMAP reads. The Uid column is why the table has this shape:
-- IMAP promises a UID names the same message for the life of a folder's
-- UIDVALIDITY, so it is assigned here once and never reassigned.
--
-- A message delivered to three mailboxes is ONE file and THREE rows. Storing three
-- copies would triple the disk for a message sent to a distribution list, and make
-- deduplication a background job that has to prove two files are identical rather
-- than a property of the schema.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.Deliveries (
    Id            UNIQUEIDENTIFIER  NOT NULL,
    MessageId     UNIQUEIDENTIFIER  NOT NULL,
    MailboxId     UNIQUEIDENTIFIER  NOT NULL,
    FolderId      UNIQUEIDENTIFIER  NOT NULL,

    -- Strictly increasing within the folder, from MailboxFolders.NextUid. Never
    -- reused, never reordered: a client that cached UID 42 must still find the same
    -- message there, or the cache silently serves the wrong mail.
    Uid           BIGINT            NOT NULL,

    -- IMAP system flags as a bitmask. 1 Seen, 2 Answered, 4 Flagged, 8 Deleted,
    -- 16 Draft, 32 Recent.
    Flags         INT               NOT NULL CONSTRAINT DF_Deliveries_Flags DEFAULT (0),

    -- The envelope recipient this delivery came from, so an alias expansion can be
    -- traced back to the address the sender actually wrote.
    RecipientId   UNIQUEIDENTIFIER  NULL,

    -- IMAP INTERNALDATE. Distinct from the message's Date: header, which the sender
    -- wrote and may have got wrong by years.
    InternalDate  DATETIMEOFFSET(7) NOT NULL,

    CreatedUtc    DATETIMEOFFSET(7) NOT NULL,

    CONSTRAINT PK_Deliveries PRIMARY KEY NONCLUSTERED (Id),

    -- NO ACTION is SQL Server's spelling of RESTRICT. Deleting a message row out
    -- from under a folder would leave IMAP clients with cached UIDs pointing at
    -- nothing; expunging is a deliberate operation, not a side effect of tidying.
    CONSTRAINT FK_Deliveries_Message
        FOREIGN KEY (MessageId) REFERENCES dbo.Messages (Id) ON DELETE NO ACTION,

    CONSTRAINT FK_Deliveries_Mailbox
        FOREIGN KEY (MailboxId) REFERENCES dbo.Mailboxes (Id) ON DELETE NO ACTION,

    CONSTRAINT FK_Deliveries_Folder
        FOREIGN KEY (FolderId) REFERENCES dbo.MailboxFolders (Id) ON DELETE NO ACTION,

    -- SET NULL rather than NO ACTION: losing the provenance of a delivery is
    -- acceptable, losing the delivery is not.
    CONSTRAINT FK_Deliveries_Recipient
        FOREIGN KEY (RecipientId) REFERENCES dbo.MessageRecipients (Id) ON DELETE SET NULL
);
GO

-- Clustered on (FolderId, Uid): every IMAP read is "this folder, in UID order", so
-- the physical order matches the only access pattern that matters.
CREATE UNIQUE CLUSTERED INDEX UX_Deliveries_Folder_Uid ON dbo.Deliveries (FolderId, Uid);
GO

CREATE INDEX IX_Deliveries_MailboxId ON dbo.Deliveries (MailboxId);
GO

CREATE INDEX IX_Deliveries_MessageId ON dbo.Deliveries (MessageId);
GO

-- The same message must not be delivered to the same folder twice. Without this, a
-- retried delivery after a partial failure silently duplicates mail.
CREATE UNIQUE INDEX UX_Deliveries_Folder_Message ON dbo.Deliveries (FolderId, MessageId);
GO
