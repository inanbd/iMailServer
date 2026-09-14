-- =============================================================================
-- AetherMail Server - mailbox administration (Microsoft SQL Server)
-- Milestone 5
--
-- The SQL Server counterpart of the SQLite 0005 script. The two are kept
-- deliberately in step; anything that cannot be expressed identically is called
-- out in a comment rather than allowed to diverge silently.
--
-- Adds one column to Mailboxes and is otherwise purely additive, so it carries no
-- destructive directive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- Mailboxes gains a combined access-flags column, backfilled from the three
-- booleans created in 0001 so an upgrade does not change what any existing mailbox
-- is allowed to do. MailboxAccess: 1 Imap, 2 Pop3, 4 Submission.
-- -----------------------------------------------------------------------------
ALTER TABLE dbo.Mailboxes
    ADD AccessFlags INT NOT NULL CONSTRAINT DF_Mailboxes_AccessFlags DEFAULT (5);
GO

UPDATE dbo.Mailboxes
SET    AccessFlags = (CASE WHEN ImapEnabled       = 1 THEN 1 ELSE 0 END)
                   + (CASE WHEN Pop3Enabled       = 1 THEN 2 ELSE 0 END)
                   + (CASE WHEN SubmissionEnabled = 1 THEN 4 ELSE 0 END);
GO


-- -----------------------------------------------------------------------------
-- MailboxCredentials: the password that authenticates access to one mailbox.
--
-- Argon2id verifiers in PHC string format, exactly like the administrator's.
--
-- This table is why CRAM-MD5 and DIGEST-MD5 are not offered: those need the server
-- to hold something it can compute a challenge response from, which means storing
-- recoverable passwords. One database read would then yield every user's password,
-- and users reuse them.
--
-- Separate from Mailboxes because lockout state changes on every failed login, and
-- a brute-force attempt should rewrite this row rather than the one delivery reads
-- on every message.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.MailboxCredentials (
    Id                  UNIQUEIDENTIFIER  NOT NULL,
    MailboxId           UNIQUEIDENTIFIER  NOT NULL,

    PasswordHash        NVARCHAR(1024)    NOT NULL,

    MustChangePassword  BIT               NOT NULL
        CONSTRAINT DF_MailboxCredentials_MustChange DEFAULT (0),

    -- PERSISTED lockout state.
    ConsecutiveFailures INT               NOT NULL
        CONSTRAINT DF_MailboxCredentials_Failures DEFAULT (0),
    LastFailureUtc      DATETIMEOFFSET(7) NULL,
    LockedOutUntilUtc   DATETIMEOFFSET(7) NULL,

    LastSuccessUtc      DATETIMEOFFSET(7) NULL,

    CreatedUtc          DATETIMEOFFSET(7) NOT NULL,
    PasswordChangedUtc  DATETIMEOFFSET(7) NULL,

    CONSTRAINT PK_MailboxCredentials PRIMARY KEY NONCLUSTERED (Id),

    -- CASCADE here, unlike elsewhere in this schema: a credential references
    -- nothing on disk, so cascading leaves nothing orphaned, and a credential
    -- outliving its mailbox would authenticate against nothing.
    CONSTRAINT FK_MailboxCredentials_Mailbox
        FOREIGN KEY (MailboxId) REFERENCES dbo.Mailboxes (Id) ON DELETE CASCADE,

    CONSTRAINT CK_MailboxCredentials_Failures
        CHECK (ConsecutiveFailures >= 0)
);

-- One credential per mailbox today; UNIQUE rather than a primary key so that
-- application passwords - several per mailbox, each revocable - remain a widening
-- of this index rather than a re-key.
CREATE UNIQUE CLUSTERED INDEX UX_MailboxCredentials_Mailbox
    ON dbo.MailboxCredentials (MailboxId);


-- -----------------------------------------------------------------------------
-- Aliases: an address that forwards rather than storing.
--
-- Targets are newline-separated in one column: read only as a complete set, never
-- queried individually, replaced wholesale on edit. A child table would add a join
-- to a lookup performed on every RCPT TO.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.Aliases (
    Id          UNIQUEIDENTIFIER  NOT NULL,
    DomainId    UNIQUEIDENTIFIER  NOT NULL,

    LocalPart   NVARCHAR(64)      NOT NULL,

    -- Normalised full address: the lookup and uniqueness key. 320 is the RFC 5321
    -- maximum (64 local-part + @ + 255 domain).
    Address     NVARCHAR(320)     NOT NULL,

    Targets     NVARCHAR(MAX)     NOT NULL,

    Description NVARCHAR(512)     NULL,

    IsEnabled   BIT               NOT NULL CONSTRAINT DF_Aliases_IsEnabled DEFAULT (1),

    CreatedUtc  DATETIMEOFFSET(7) NOT NULL,
    ModifiedUtc DATETIMEOFFSET(7) NULL,

    CONSTRAINT PK_Aliases PRIMARY KEY NONCLUSTERED (Id),

    CONSTRAINT FK_Aliases_Domains
        FOREIGN KEY (DomainId) REFERENCES dbo.Domains (Id) ON DELETE NO ACTION
);

-- An address is either a mailbox or an alias, never both. No SQL engine can express
-- that across two tables, so this makes aliases unique among themselves and the
-- create handlers check the other table. The loser of the race gets a constraint
-- violation rather than a silently ambiguous address.
CREATE UNIQUE CLUSTERED INDEX UX_Aliases_Address ON dbo.Aliases (Address);

CREATE INDEX IX_Aliases_DomainId ON dbo.Aliases (DomainId);


-- -----------------------------------------------------------------------------
-- MailboxFolders: the IMAP folder tree. Created in Milestone 5, filled in
-- Milestone 10.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.MailboxFolders (
    Id           UNIQUEIDENTIFIER  NOT NULL,
    MailboxId    UNIQUEIDENTIFIER  NOT NULL,

    -- Full path, '/' separated.
    Path         NVARCHAR(512)     NOT NULL,

    -- FolderSpecialUse: 0 None … 6 Archive (RFC 6154).
    SpecialUse   INT               NOT NULL CONSTRAINT DF_MailboxFolders_Special DEFAULT (0),

    -- Assigned once and NEVER changed: it is the promise to a client that its
    -- cached UIDs still name the same messages.
    UidValidity  BIGINT            NOT NULL,

    NextUid      BIGINT            NOT NULL CONSTRAINT DF_MailboxFolders_NextUid DEFAULT (1),

    IsSubscribed BIT               NOT NULL CONSTRAINT DF_MailboxFolders_Sub DEFAULT (1),

    CreatedUtc   DATETIMEOFFSET(7) NOT NULL,
    ModifiedUtc  DATETIMEOFFSET(7) NULL,

    CONSTRAINT PK_MailboxFolders PRIMARY KEY NONCLUSTERED (Id),

    -- NO ACTION is SQL Server's RESTRICT: a folder holds messages, and messages are
    -- files on disk. Cascading would delete rows and strand files.
    CONSTRAINT FK_MailboxFolders_Mailbox
        FOREIGN KEY (MailboxId) REFERENCES dbo.Mailboxes (Id) ON DELETE NO ACTION,

    CONSTRAINT CK_MailboxFolders_Uid
        CHECK (UidValidity > 0 AND NextUid > 0)
);

CREATE UNIQUE CLUSTERED INDEX UX_MailboxFolders_Path
    ON dbo.MailboxFolders (MailboxId, Path);

-- At most one folder per special use per mailbox. A filtered unique index is the
-- SQL Server spelling of SQLite's partial index.
CREATE UNIQUE INDEX UX_MailboxFolders_SpecialUse
    ON dbo.MailboxFolders (MailboxId, SpecialUse)
    WHERE SpecialUse <> 0;
