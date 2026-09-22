-- =============================================================================
-- AetherMail Server - quarantine (SQL Server)
-- Milestone 12
--
-- Purely additive: new tables and indexes. Nothing existing is altered or
-- dropped, so this carries no destructive directive.
--
-- The SQLite script is the one with the full reasoning; this is its twin and
-- differs only where the dialect forces it.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- QuarantinedMessages: mail the filter held and delivered to nobody. The
-- content is not copied - the Messages row already names it, and release reads
-- the same file delivery would have. See the SQLite script's remarks.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.QuarantinedMessages (
    Id              UNIQUEIDENTIFIER  NOT NULL,
    MessageId       UNIQUEIDENTIFIER  NOT NULL,

    ReversePath     NVARCHAR(320)     NULL,
    RemoteAddress   NVARCHAR(45)      NOT NULL,

    -- FLOAT rather than DECIMAL: the signals that sum to it are fractional
    -- weights an operator tunes, not money, and rounding one to a scale would
    -- make the stored score disagree with the arithmetic that produced it.
    Score           FLOAT             NOT NULL,

    Summary         NVARCHAR(1024)    NOT NULL,

    -- QuarantineStatus: 0 Held, 1 Released, 2 Discarded.
    Status          INT               NOT NULL,

    QuarantinedUtc  DATETIMEOFFSET(7) NOT NULL,
    ResolvedUtc     DATETIMEOFFSET(7) NULL,
    ResolvedBy      NVARCHAR(256)     NULL,
    ExpiresUtc      DATETIMEOFFSET(7) NOT NULL,

    CONSTRAINT PK_QuarantinedMessages PRIMARY KEY NONCLUSTERED (Id),

    CONSTRAINT FK_QuarantinedMessages_Message
        FOREIGN KEY (MessageId) REFERENCES dbo.Messages (Id) ON DELETE CASCADE,

    CONSTRAINT CK_QuarantinedMessages_Status CHECK (Status IN (0, 1, 2)),

    CONSTRAINT CK_QuarantinedMessages_Resolved CHECK (
        (Status = 0 AND ResolvedUtc IS NULL) OR
        (Status <> 0 AND ResolvedUtc IS NOT NULL))
);
GO

CREATE UNIQUE INDEX UX_QuarantinedMessages_MessageId
    ON dbo.QuarantinedMessages (MessageId);
GO

-- Filtered on Status: a long-running installation's resolved rows accumulate
-- without bound and are never what the default view asks for.
CREATE INDEX IX_QuarantinedMessages_Held
    ON dbo.QuarantinedMessages (QuarantinedUtc DESC)
    WHERE Status = 0;
GO

CREATE INDEX IX_QuarantinedMessages_Expiry
    ON dbo.QuarantinedMessages (ExpiresUtc)
    WHERE Status = 0;
GO


-- -----------------------------------------------------------------------------
-- QuarantineSignals: why the message was held. These describe and never quote -
-- a listing is read under ViewServerState and the message needs
-- ReadMessageContent. See the SQLite script.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.QuarantineSignals (
    Id                    UNIQUEIDENTIFIER NOT NULL,
    QuarantinedMessageId  UNIQUEIDENTIFIER NOT NULL,

    Name                  NVARCHAR(64)     NOT NULL,
    Score                 FLOAT            NOT NULL,
    Detail                NVARCHAR(256)    NOT NULL,
    Ordinal               INT              NOT NULL,

    CONSTRAINT PK_QuarantineSignals PRIMARY KEY NONCLUSTERED (Id),

    CONSTRAINT FK_QuarantineSignals_Message
        FOREIGN KEY (QuarantinedMessageId) REFERENCES dbo.QuarantinedMessages (Id) ON DELETE CASCADE
);
GO

CREATE INDEX IX_QuarantineSignals_Message
    ON dbo.QuarantineSignals (QuarantinedMessageId, Ordinal);
GO
