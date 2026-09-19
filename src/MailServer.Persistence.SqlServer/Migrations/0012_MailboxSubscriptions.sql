-- =============================================================================
-- AetherMail Server - IMAP subscription list and UIDVALIDITY high-water mark (Microsoft SQL Server)
-- Milestone 10
--
-- Purely additive: one new table, its index, and a seed from the column it
-- supersedes. No existing table is altered, so this carries no destructive
-- directive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- MailboxSubscriptions: the names a mailbox's owner has declared "active", as
-- LSUB reports them.
--
-- A TABLE OF NAMES, NOT A FLAG ON A FOLDER, and the difference is a MUST NOT in
-- the specification. RFC 3501 6.3.6: a server "MUST NOT unilaterally remove an
-- existing mailbox name from the subscription list even if a mailbox by that
-- name no longer exists", and the RFC explains why in a note: "a server site can
-- choose to routinely remove a mailbox with a well-known name (e.g.,
-- "system-alerts") after its contents expire, with the intention of recreating
-- it when new contents are appropriate."
--
-- MailboxFolders.IsSubscribed could not express that: a subscription stored on a
-- folder row dies with the row, so DELETE would silently unsubscribe the user
-- from a name they asked to keep following. Once DELETE exists - it does, as of
-- this milestone - that flag becomes a live violation rather than a latent one.
--
-- There is deliberately NO foreign key to MailboxFolders. The whole point is
-- that a subscription outlives the folder it names.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.MailboxSubscriptions (
    MailboxId  UNIQUEIDENTIFIER  NOT NULL,

    -- The name as the user subscribed to it, decoded. Matched exactly, like
    -- every other folder path in this schema.
    Path       NVARCHAR(512)     NOT NULL,

    CreatedUtc DATETIMEOFFSET(7) NOT NULL,

    PRIMARY KEY (MailboxId, Path),

    FOREIGN KEY (MailboxId) REFERENCES dbo.Mailboxes (Id) ON DELETE CASCADE
);


-- LSUB reads every subscription of one mailbox and filters by pattern in memory,
-- so the mailbox is the only lookup key the query needs.
CREATE INDEX IX_MailboxSubscriptions_Mailbox
    ON dbo.MailboxSubscriptions (MailboxId);


-- -----------------------------------------------------------------------------
-- Seed from the flag this table supersedes, so no user is silently unsubscribed
-- from everything by the upgrade. MailboxFolders.IsSubscribed is left in place
-- and is no longer read; removing a column alters a table, which would make this
-- migration destructive and therefore unapplicable until the backup subsystem
-- lands in Milestone 13. It is dropped there.
-- -----------------------------------------------------------------------------
INSERT INTO dbo.MailboxSubscriptions (MailboxId, Path, CreatedUtc)
SELECT MailboxId, Path, CreatedUtc
FROM   dbo.MailboxFolders
WHERE  IsSubscribed <> 0;


-- -----------------------------------------------------------------------------
-- MailboxUidValidity: the highest UIDVALIDITY ever issued in a mailbox.
--
-- A HIGH-WATER MARK THAT OUTLIVES A FOLDER, for the same reason the subscription
-- list does. RFC 3501 6.3.3 requires a mailbox created with a deleted mailbox's
-- name to use UIDs "greater than any unique identifiers used in the previous
-- incarnation UNLESS the new incarnation has a different unique identifier
-- validity value". This server takes the exception rather than preserving a UID
-- counter per deleted name - so the UIDVALIDITY it issues must genuinely differ,
-- every time, and a value derived from surviving rows cannot promise that: the
-- deleted folder's value went with its row.
--
-- Without this table, deleting "Receipts" and creating it again inside the same
-- clock second reissues the same UIDVALIDITY with UIDs restarting at 1, and a
-- client serves cached mail under UIDs that now name different messages. That is
-- the quiet, wrong-mail-to-the-user failure this subsystem is most dangerous for.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.MailboxUidValidity (
    MailboxId UNIQUEIDENTIFIER NOT NULL PRIMARY KEY,

    -- Monotonic. Seeded from the clock and never allowed to go backwards.
    Highest   BIGINT           NOT NULL,

    FOREIGN KEY (MailboxId) REFERENCES dbo.Mailboxes (Id) ON DELETE CASCADE
);


-- Seed from the folders that exist, so an upgrade never issues a value one of
-- them already used.
INSERT INTO dbo.MailboxUidValidity (MailboxId, Highest)
SELECT MailboxId, MAX(UidValidity)
FROM   dbo.MailboxFolders
GROUP BY MailboxId;
