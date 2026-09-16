-- =============================================================================
-- AetherMail Server - DKIM verification results (SQLite)
-- Milestone 9
--
-- Purely additive: one new table and its index. No existing table is altered,
-- so this carries no destructive directive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- DkimVerificationResults: the outcome of verifying each DKIM-Signature header
-- found on a received message.
--
-- One row per signature, not one row per message - a message can legitimately
-- carry several. Never a mutation of the stored message: the archived
-- original is exactly what was received, and this table is metadata recorded
-- alongside it, the same relationship DeliveryAttempts has to
-- OutboundQueueItems.
-- -----------------------------------------------------------------------------
CREATE TABLE DkimVerificationResults (
    Id             TEXT    NOT NULL PRIMARY KEY,
    MessageId      TEXT    NOT NULL,

    -- 0-based position among the message's DKIM-Signature headers, in wire order.
    SignatureIndex INTEGER NOT NULL,

    -- DkimVerificationResult: 0 None, 1 Pass, 2 Fail, 3 TempError, 4 PermError.
    Result         INTEGER NOT NULL,

    -- The signature's d= value, present whenever it at least parsed. What DMARC
    -- alignment (a later step) compares against the From: header's domain.
    SigningDomain  TEXT    NULL,

    Diagnostic     TEXT    NULL,

    CreatedUtc     TEXT    NOT NULL,

    CONSTRAINT FK_DkimVerificationResults_Message
        FOREIGN KEY (MessageId) REFERENCES Messages (Id) ON DELETE CASCADE,

    CONSTRAINT CK_DkimVerificationResults_Result CHECK (Result BETWEEN 0 AND 4),
    CONSTRAINT CK_DkimVerificationResults_SignatureIndex CHECK (SignatureIndex >= 0)
) STRICT;

-- A future Authentication-Results composition step and DMARC alignment both
-- read every result for one message together.
CREATE INDEX IX_DkimVerificationResults_MessageId
    ON DkimVerificationResults (MessageId, SignatureIndex);
