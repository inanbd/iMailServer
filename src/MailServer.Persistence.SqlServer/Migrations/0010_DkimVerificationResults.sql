-- =============================================================================
-- AetherMail Server - DKIM verification results (Microsoft SQL Server)
-- Milestone 9
--
-- The SQL Server counterpart of the SQLite 0010 script.
--
-- Purely additive: no existing table is altered, so this is not marked
-- @Destructive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- DkimVerificationResults: the outcome of verifying each DKIM-Signature header
-- found on a received message. One row per signature, not one row per
-- message. Never a mutation of the stored message - see the SQLite script's
-- remarks.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.DkimVerificationResults (
    Id             UNIQUEIDENTIFIER  NOT NULL,
    MessageId      UNIQUEIDENTIFIER  NOT NULL,

    -- 0-based position among the message's DKIM-Signature headers, in wire order.
    SignatureIndex INT               NOT NULL,

    -- DkimVerificationResult: 0 None, 1 Pass, 2 Fail, 3 TempError, 4 PermError.
    Result         INT               NOT NULL,

    -- The signature's d= value, present whenever it at least parsed.
    SigningDomain  VARCHAR(255)      NULL,

    Diagnostic     NVARCHAR(1024)    NULL,

    CreatedUtc     DATETIMEOFFSET(7) NOT NULL,

    CONSTRAINT PK_DkimVerificationResults PRIMARY KEY NONCLUSTERED (Id),

    CONSTRAINT FK_DkimVerificationResults_Message
        FOREIGN KEY (MessageId) REFERENCES dbo.Messages (Id) ON DELETE CASCADE,

    CONSTRAINT CK_DkimVerificationResults_Result CHECK (Result BETWEEN 0 AND 4),
    CONSTRAINT CK_DkimVerificationResults_SignatureIndex CHECK (SignatureIndex >= 0)
);

-- A future Authentication-Results composition step and DMARC alignment both
-- read every result for one message together.
CREATE CLUSTERED INDEX IX_DkimVerificationResults_MessageId
    ON dbo.DkimVerificationResults (MessageId, SignatureIndex);
