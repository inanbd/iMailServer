-- =============================================================================
-- AetherMail Server - collected TLS reports (SQL Server)
-- Milestone 11
--
-- Purely additive: new tables and indexes. Nothing existing is altered or
-- dropped, so this carries no destructive directive.
--
-- The SQLite script is the one with the full reasoning; this is its twin and
-- differs only where the dialect forces it.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- TlsReports: RFC 8460 reports other senders delivered to this domain's rua
-- address. Unauthenticated claims about us, not findings - see the SQLite
-- script's remarks.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.TlsReports (
    Id                      UNIQUEIDENTIFIER  NOT NULL,

    -- Lower-cased by the collector before it is written. This server's own
    -- choice rather than the column's collation, so the unique index below
    -- folds case identically on both providers - see docs/IMAP.md's note on
    -- what inheriting a collation costs.
    PolicyDomain            NVARCHAR(255)     NOT NULL,

    OrganizationName        NVARCHAR(255)     NULL,
    ContactInfo             NVARCHAR(320)     NULL,
    ReportId                NVARCHAR(255)     NULL,

    StartUtc                DATETIMEOFFSET(7) NULL,
    EndUtc                  DATETIMEOFFSET(7) NULL,

    SuccessfulSessionCount  BIGINT            NOT NULL,
    FailedSessionCount      BIGINT            NOT NULL,

    Summary                 NVARCHAR(1024)    NOT NULL,
    CollectedUtc            DATETIMEOFFSET(7) NOT NULL,

    CONSTRAINT PK_TlsReports PRIMARY KEY NONCLUSTERED (Id),
    CONSTRAINT CK_TlsReports_SuccessfulSessionCount CHECK (SuccessfulSessionCount >= 0),
    CONSTRAINT CK_TlsReports_FailedSessionCount CHECK (FailedSessionCount >= 0)
);
GO

-- De-duplication, so a mailbox scanned twice does not double every number an
-- operator reads. Filtered rather than plain, because SQL Server treats NULLs
-- as equal in a unique index and would otherwise permit only one report with no
-- id across the whole table.
CREATE UNIQUE INDEX UX_TlsReports_Identity
    ON dbo.TlsReports (PolicyDomain, OrganizationName, ReportId)
    WHERE ReportId IS NOT NULL;
GO

CREATE INDEX IX_TlsReports_Domain_Collected
    ON dbo.TlsReports (PolicyDomain, CollectedUtc DESC);
GO


-- -----------------------------------------------------------------------------
-- TlsReportFailures: one row per result type per report, already grouped by
-- impact - see the SQLite script for why grouping happens before storage.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.TlsReportFailures (
    Id                   UNIQUEIDENTIFIER NOT NULL,
    TlsReportId          UNIQUEIDENTIFIER NOT NULL,

    -- The wire name rather than the enum's number: RFC 8460 4.3 is extensible,
    -- and a number would lose a type this version does not know.
    ResultType           NVARCHAR(64)     NOT NULL,

    FailedSessionCount   BIGINT           NOT NULL,
    ReceivingMxHostnames NVARCHAR(2048)   NULL,

    CONSTRAINT PK_TlsReportFailures PRIMARY KEY NONCLUSTERED (Id),

    CONSTRAINT FK_TlsReportFailures_Report
        FOREIGN KEY (TlsReportId) REFERENCES dbo.TlsReports (Id) ON DELETE CASCADE,

    CONSTRAINT CK_TlsReportFailures_FailedSessionCount CHECK (FailedSessionCount >= 0)
);
GO

CREATE INDEX IX_TlsReportFailures_ReportId
    ON dbo.TlsReportFailures (TlsReportId);
GO


-- -----------------------------------------------------------------------------
-- TlsReportSources: the messages already looked at, so a pass does not re-read
-- them and a message that is not a report is not re-examined forever.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.TlsReportSources (
    MessageId   UNIQUEIDENTIFIER  NOT NULL,
    TlsReportId UNIQUEIDENTIFIER  NULL,
    Error       NVARCHAR(1024)    NULL,
    ExaminedUtc DATETIMEOFFSET(7) NOT NULL,

    CONSTRAINT PK_TlsReportSources PRIMARY KEY NONCLUSTERED (MessageId),

    CONSTRAINT FK_TlsReportSources_Message
        FOREIGN KEY (MessageId) REFERENCES dbo.Messages (Id) ON DELETE CASCADE,

    CONSTRAINT FK_TlsReportSources_Report
        FOREIGN KEY (TlsReportId) REFERENCES dbo.TlsReports (Id)
);
GO
