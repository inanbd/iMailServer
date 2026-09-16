-- =============================================================================
-- AetherMail Server - DMARC verification results (Microsoft SQL Server)
-- Milestone 9
--
-- The SQL Server counterpart of the SQLite 0011 script.
--
-- Purely additive: no existing table is altered, so this is not marked
-- @Destructive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- DmarcVerificationResults: the outcome of evaluating DMARC alignment for one
-- received message. One row per message. Never a mutation of the stored
-- message - see the SQLite script's remarks.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.DmarcVerificationResults (
    Id                UNIQUEIDENTIFIER  NOT NULL,
    MessageId         UNIQUEIDENTIFIER  NOT NULL,

    -- DmarcResult: 0 Fail, 1 Pass. NULL means DMARC did not apply to this
    -- message at all - see the SQLite script's remarks.
    Result            INT               NULL,

    -- DmarcPolicy actually requested for this message, after sp=/p=
    -- resolution and pct= sampling: 0 None, 1 Quarantine, 2 Reject.
    Disposition       INT               NOT NULL,

    -- DmarcAlignedMechanism flags: 0 None, 1 Spf, 2 Dkim, 3 both.
    AlignedMechanisms INT               NOT NULL,

    FromDomain        VARCHAR(255)      NULL,
    PolicyDomain      VARCHAR(255)      NULL,
    Diagnostic        NVARCHAR(1024)    NULL,

    CreatedUtc        DATETIMEOFFSET(7) NOT NULL,

    CONSTRAINT PK_DmarcVerificationResults PRIMARY KEY NONCLUSTERED (Id),

    CONSTRAINT FK_DmarcVerificationResults_Message
        FOREIGN KEY (MessageId) REFERENCES dbo.Messages (Id) ON DELETE CASCADE,

    CONSTRAINT CK_DmarcVerificationResults_Result CHECK (Result BETWEEN 0 AND 1),
    CONSTRAINT CK_DmarcVerificationResults_Disposition CHECK (Disposition BETWEEN 0 AND 2),
    CONSTRAINT CK_DmarcVerificationResults_AlignedMechanisms CHECK (AlignedMechanisms BETWEEN 0 AND 3)
);

-- A future Authentication-Results composition step reads this alongside a
-- message's DkimVerificationResults rows.
CREATE CLUSTERED INDEX IX_DmarcVerificationResults_MessageId
    ON dbo.DmarcVerificationResults (MessageId);
