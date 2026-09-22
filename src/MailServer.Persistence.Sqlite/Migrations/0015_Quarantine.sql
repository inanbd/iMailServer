-- =============================================================================
-- AetherMail Server - quarantine (SQLite)
-- Milestone 12
--
-- Purely additive: two new tables and their indexes. Nothing existing is altered
-- or dropped, so this carries no destructive directive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- QuarantinedMessages: mail the filter held, and did not deliver to anybody.
--
-- WHAT QUARANTINE IS FOR. Junk is the right answer for "probably spam": the
-- recipient still has it and can still disagree. Quarantine is for what should
-- not reach a recipient even in a junk folder - malware, an executable
-- attachment - but which a human should be able to look at and release. The
-- recipient is never notified, because a notification is how a quarantine
-- becomes a delivery channel for the very content it is holding back.
--
-- WHY THE CONTENT IS NOT COPIED. The message is already in the store and the
-- Messages row already names it; this table holds the verdict and the state, and
-- release reads the same file delivery would have. Copying would double the disk
-- a held message costs and would create a second copy nothing else knows to
-- delete.
--
-- WHY THERE IS NO 'Released' CONTENT DELETION. Releasing delivers the message
-- and leaves this row behind as a record of what was held and who let it
-- through. An operator asking "did we release that?" six months later has an
-- answer, and the answer survives the message being expunged from the mailbox
-- it was released into.
-- -----------------------------------------------------------------------------
CREATE TABLE QuarantinedMessages (
    Id              TEXT    NOT NULL PRIMARY KEY,

    -- The held message. ON DELETE CASCADE because a quarantine row naming a
    -- message that no longer exists could neither be released nor read, and
    -- would be a row an operator can only be confused by.
    MessageId       TEXT    NOT NULL,

    -- The envelope sender as written, or NULL for the null reverse path. Copied
    -- rather than joined because it is the first thing an operator reads in the
    -- listing, and because a bounce's null reverse path is itself informative.
    ReversePath     TEXT    NULL,

    -- The peer that delivered it. Text rather than a number so IPv6 is
    -- representable, matching every other address column in this schema.
    RemoteAddress   TEXT    NOT NULL,

    -- The score the checks summed to. Stored as REAL because the signals that
    -- produced it are fractional; an integer column would round a 4.5 to a 4 or
    -- a 5 and make an operator's arithmetic disagree with the server's.
    Score           REAL    NOT NULL,

    -- The one-line verdict composed by FilterVerdict.Summarise when the message
    -- was held. Stored rather than recomposed so a listing does not rebuild
    -- every verdict to render a line, and so the wording does not change under
    -- an operator after an upgrade.
    Summary         TEXT    NOT NULL,

    -- QuarantineStatus: 0 Held, 1 Released, 2 Discarded.
    Status          INTEGER NOT NULL,

    QuarantinedUtc  TEXT    NOT NULL,

    -- When the hold was resolved, and by whom. NULL while Status is Held.
    ResolvedUtc     TEXT    NULL,

    -- The administrator who released or discarded it. A quarantine that could
    -- not say who let a message through would make the audit trail's account of
    -- the decision incomplete at exactly the point it matters.
    ResolvedBy      TEXT    NULL,

    -- When a retention sweep may remove this row and the content with it. Set at
    -- hold time rather than computed on read, so that changing the retention
    -- setting does not retroactively expire what is already held.
    ExpiresUtc      TEXT    NOT NULL,

    CONSTRAINT FK_QuarantinedMessages_Message
        FOREIGN KEY (MessageId) REFERENCES Messages (Id) ON DELETE CASCADE,

    CONSTRAINT CK_QuarantinedMessages_Status CHECK (Status IN (0, 1, 2)),

    -- A resolved row must say when, and an unresolved one must not: the two
    -- columns are one fact and may not disagree.
    CONSTRAINT CK_QuarantinedMessages_Resolved CHECK (
        (Status = 0 AND ResolvedUtc IS NULL) OR
        (Status <> 0 AND ResolvedUtc IS NOT NULL))
) STRICT;

-- One message is held once. A second verdict on the same message is a bug in
-- the delivery path, and a unique index is how it surfaces as an error rather
-- than as two rows an operator has to release twice.
CREATE UNIQUE INDEX UX_QuarantinedMessages_MessageId
    ON QuarantinedMessages (MessageId);

-- The listing is "what is held, newest first". A partial index because a
-- long-running installation's released and discarded rows accumulate without
-- bound and are never what the default view asks for.
CREATE INDEX IX_QuarantinedMessages_Held
    ON QuarantinedMessages (QuarantinedUtc DESC)
    WHERE Status = 0;

-- The retention sweep's predicate.
CREATE INDEX IX_QuarantinedMessages_Expiry
    ON QuarantinedMessages (ExpiresUtc)
    WHERE Status = 0;


-- -----------------------------------------------------------------------------
-- QuarantineSignals: why the message was held.
--
-- WHY THESE ARE STORED AT ALL. The score alone cannot be argued with, and the
-- only question an operator actually has about a held message is "why?". A
-- release decision made without the reasons is a coin toss.
--
-- WHAT THEY MAY NOT CONTAIN. A signal describes and never quotes: no subject
-- line, no body text, no address out of the message. A quarantine listing is
-- read under ViewServerState and the message itself needs ReadMessageContent,
-- so a signal carrying content would be a way to read mail with the weaker of
-- the two permissions. FilterSignal is where that rule lives; this is where it
-- would be broken if it were broken.
-- -----------------------------------------------------------------------------
CREATE TABLE QuarantineSignals (
    Id                    TEXT    NOT NULL PRIMARY KEY,
    QuarantinedMessageId  TEXT    NOT NULL,

    -- The check's stable identifier, e.g. BLOCKED_ATTACHMENT. Text rather than a
    -- number because an operator tunes weights by naming signals in
    -- configuration, so the name is part of the product's surface.
    Name                  TEXT    NOT NULL,

    Score                 REAL    NOT NULL,
    Detail                TEXT    NOT NULL,

    -- The order the checks produced them, so the stored explanation reads the
    -- way the one in the log did.
    Ordinal               INTEGER NOT NULL,

    CONSTRAINT FK_QuarantineSignals_Message
        FOREIGN KEY (QuarantinedMessageId) REFERENCES QuarantinedMessages (Id) ON DELETE CASCADE
) STRICT;

CREATE INDEX IX_QuarantineSignals_Message
    ON QuarantineSignals (QuarantinedMessageId, Ordinal);
