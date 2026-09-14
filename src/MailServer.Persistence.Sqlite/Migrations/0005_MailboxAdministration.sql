-- =============================================================================
-- AetherMail Server - mailbox administration (SQLite)
-- Milestone 5
--
-- Adds credentials, aliases and IMAP folders. The Mailboxes table itself was
-- created in 0001; this migration adds one column to it and is otherwise purely
-- additive, so it carries no destructive directive and needs no pre-upgrade
-- backup.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- Mailboxes gains a combined access-flags column.
--
-- The three booleans from 0001 (ImapEnabled, Pop3Enabled, SubmissionEnabled) stay
-- as they are; this is the same information as a flags value, because the question
-- callers actually ask is "may this credential submit mail", which is one question
-- rather than three column reads.
--
-- Backfilled from the existing booleans rather than defaulted, so an upgrade does
-- not silently change what an existing mailbox is allowed to do. MailboxAccess:
-- 1 Imap, 2 Pop3, 4 Submission.
-- -----------------------------------------------------------------------------
ALTER TABLE Mailboxes ADD COLUMN AccessFlags INTEGER NOT NULL DEFAULT 5;

UPDATE Mailboxes
SET    AccessFlags = (CASE WHEN ImapEnabled       = 1 THEN 1 ELSE 0 END)
                   + (CASE WHEN Pop3Enabled       = 1 THEN 2 ELSE 0 END)
                   + (CASE WHEN SubmissionEnabled = 1 THEN 4 ELSE 0 END);


-- -----------------------------------------------------------------------------
-- MailboxCredentials: the password that authenticates access to one mailbox.
--
-- Argon2id verifiers in PHC string format, exactly like the administrator's. The
-- work factors travel with each hash, so raising them does not invalidate existing
-- passwords and an old hash is upgraded on the next successful login.
--
-- This table is WHY CRAM-MD5 and DIGEST-MD5 are not offered. Those mechanisms need
-- the server to hold something it can compute a challenge response from - in
-- practice the password, or a reversible transformation of it. Storing recoverable
-- mailbox passwords turns one database read into every user's password, and users
-- reuse them. AUTH PLAIN and AUTH LOGIN over TLS send the password to a server that
-- verifies and discards it, which is strictly better.
--
-- A separate table from Mailboxes because lockout state changes on every failed
-- login: keeping it here means a brute-force attempt rewrites this row rather than
-- the mailbox row that delivery reads on every message.
-- -----------------------------------------------------------------------------
CREATE TABLE MailboxCredentials (
    Id                  TEXT    NOT NULL PRIMARY KEY,
    MailboxId           TEXT    NOT NULL,

    PasswordHash        TEXT    NOT NULL,

    -- Recorded but not enforced: neither IMAP nor SMTP has a channel to tell a
    -- client "change your password". It exists so the admin UI can show which
    -- mailboxes are still on an administrator-set password.
    MustChangePassword  INTEGER NOT NULL DEFAULT 0,

    -- PERSISTED lockout state. A counter that reset when the service restarted
    -- would be no lockout at all.
    ConsecutiveFailures INTEGER NOT NULL DEFAULT 0,
    LastFailureUtc      TEXT    NULL,
    LockedOutUntilUtc   TEXT    NULL,

    LastSuccessUtc      TEXT    NULL,

    CreatedUtc          TEXT    NOT NULL,
    PasswordChangedUtc  TEXT    NULL,

    -- CASCADE here, unlike everywhere else in this schema. A credential is
    -- meaningless without its mailbox and references nothing on disk, so cascading
    -- leaves nothing orphaned - and a credential outliving its mailbox would be a
    -- login that authenticates against nothing.
    CONSTRAINT FK_MailboxCredentials_Mailbox
        FOREIGN KEY (MailboxId) REFERENCES Mailboxes (Id) ON DELETE CASCADE,

    CONSTRAINT CK_MailboxCredentials_Failures
        CHECK (ConsecutiveFailures >= 0)
);

-- One credential per mailbox in Milestone 5. UNIQUE rather than a primary key on
-- MailboxId because application passwords - several credentials for one mailbox,
-- each revocable separately - are a natural later addition, and widening a unique
-- index is a smaller change than re-keying a table.
CREATE UNIQUE INDEX UX_MailboxCredentials_Mailbox ON MailboxCredentials (MailboxId);


-- -----------------------------------------------------------------------------
-- Aliases: an address that forwards rather than storing.
--
-- Targets are newline-separated in one column, for the same reason as
-- Certificates.SubjectAltNames: they are read only as a complete set, never queried
-- individually, and are replaced wholesale when the alias is edited. A child table
-- would add a join to a lookup that happens on every RCPT TO.
--
-- Targets need not be local. Forwarding externally is a normal thing to want, and
-- it is why Milestone 9's Sender Rewriting Scheme exists: forwarded mail arrives at
-- the destination from THIS server, so SPF sees this server rather than the
-- original sender.
-- -----------------------------------------------------------------------------
CREATE TABLE Aliases (
    Id          TEXT    NOT NULL PRIMARY KEY,
    DomainId    TEXT    NOT NULL,

    -- The address exactly as entered, for display.
    LocalPart   TEXT    NOT NULL,

    -- Normalised full address: the lookup and uniqueness key.
    Address     TEXT    NOT NULL,

    Targets     TEXT    NOT NULL,

    Description TEXT    NULL,

    IsEnabled   INTEGER NOT NULL DEFAULT 1,

    CreatedUtc  TEXT    NOT NULL,
    ModifiedUtc TEXT    NULL,

    CONSTRAINT FK_Aliases_Domains
        FOREIGN KEY (DomainId) REFERENCES Domains (Id) ON DELETE RESTRICT
);

-- An address is either a mailbox or an alias, never both. SQLite cannot express a
-- uniqueness constraint spanning two tables, so this index makes aliases unique
-- among themselves and the create handlers check the other table. The check is a
-- race in principle; it is also the only option short of a merged address table,
-- and the losing side of the race gets a constraint violation rather than a
-- silently ambiguous address.
CREATE UNIQUE INDEX UX_Aliases_Address ON Aliases (Address);

CREATE INDEX IX_Aliases_DomainId ON Aliases (DomainId);


-- -----------------------------------------------------------------------------
-- MailboxFolders: the IMAP folder tree.
--
-- Created in Milestone 5, filled in Milestone 10. The rows exist now because a
-- mailbox needs its standard set from the moment it exists: a client that connects
-- and finds no Sent folder creates one, named in its own locale, which is how an
-- account ends up with "Sent", "Sent Items" and "Gesendet" each holding part of the
-- history.
-- -----------------------------------------------------------------------------
CREATE TABLE MailboxFolders (
    Id           TEXT    NOT NULL PRIMARY KEY,
    MailboxId    TEXT    NOT NULL,

    -- Full path, '/' separated. A forward slash rather than a dot: a dot collides
    -- with folder names containing one, which users create constantly.
    Path         TEXT    NOT NULL,

    -- FolderSpecialUse: 0 None, 1 Inbox, 2 Sent, 3 Drafts, 4 Trash, 5 Junk,
    -- 6 Archive. RFC 6154 SPECIAL-USE, which is what stops a client guessing.
    SpecialUse   INTEGER NOT NULL DEFAULT 0,

    -- Assigned once and NEVER changed. It is the promise to a client that the UIDs
    -- it cached still name the same messages; changing it forces a full
    -- resynchronisation, and changing it accidentally does that repeatedly.
    UidValidity  INTEGER NOT NULL,

    -- Strictly increasing within a folder. UIDs start at 1; 0 is not valid.
    NextUid      INTEGER NOT NULL DEFAULT 1,

    IsSubscribed INTEGER NOT NULL DEFAULT 1,

    CreatedUtc   TEXT    NOT NULL,
    ModifiedUtc  TEXT    NULL,

    -- RESTRICT, not CASCADE: a folder holds messages, and messages are files on
    -- disk. Cascading would delete the rows and strand the files - unreclaimable
    -- storage and unrecoverable mail. Deleting a mailbox is an explicit, ordered
    -- operation that removes stored messages first.
    CONSTRAINT FK_MailboxFolders_Mailbox
        FOREIGN KEY (MailboxId) REFERENCES Mailboxes (Id) ON DELETE RESTRICT,

    CONSTRAINT CK_MailboxFolders_Uid
        CHECK (UidValidity > 0 AND NextUid > 0)
);

CREATE UNIQUE INDEX UX_MailboxFolders_Path ON MailboxFolders (MailboxId, Path);

-- At most one folder per special use per mailbox. Two folders both claiming \Sent
-- would make which one a client uses depend on row order.
CREATE UNIQUE INDEX UX_MailboxFolders_SpecialUse
    ON MailboxFolders (MailboxId, SpecialUse) WHERE SpecialUse <> 0;
