-- =============================================================================
-- AetherMail Server - initial schema (Microsoft SQL Server)
-- Milestone 1: Core Foundation
--
-- Conventions used throughout the SQL Server schema:
--   * GUIDs are UNIQUEIDENTIFIER. Primary keys are NONCLUSTERED, with a separate
--     clustered key where a natural ordering exists - see the note on Domains below.
--   * DateTimeOffset is DATETIMEOFFSET(7).
--   * Booleans are BIT.
--   * Enums are INT, matching the numeric values pinned in the Domain layer's enums.
--   * Text is NVARCHAR. Mail data is Unicode: display names, IDN U-labels and SMTPUTF8
--     local-parts are all non-ASCII by design.
--
-- This file is the SQL Server counterpart of the SQLite 0001 script. The two are kept
-- deliberately in step; anything that cannot be expressed identically is called out in
-- a comment rather than allowed to diverge silently.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- READ_COMMITTED_SNAPSHOT gives SQL Server the same reader/writer independence that
-- WAL gives SQLite: a dashboard query or an IMAP fetch never blocks behind the queue
-- processor's writes. Without it the two providers would have materially different
-- concurrency behaviour, and code correct on one would deadlock on the other.
--
-- ALTER DATABASE cannot run inside a user transaction, which is why this script is
-- marked @NoTransaction. It is idempotent and makes no schema change, so re-running it
-- after a failure is safe.
-- -----------------------------------------------------------------------------
-- @NoTransaction

DECLARE @dbName SYSNAME = DB_NAME();
DECLARE @sql NVARCHAR(MAX);

IF EXISTS (SELECT 1 FROM sys.databases
           WHERE name = @dbName AND is_read_committed_snapshot_on = 0)
BEGIN
    SET @sql = N'ALTER DATABASE ' + QUOTENAME(@dbName)
             + N' SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE;';
    EXEC sp_executesql @sql;
END
GO


-- -----------------------------------------------------------------------------
-- Domains: the mail domains this server hosts.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.Domains (
    Id                        UNIQUEIDENTIFIER NOT NULL,

    -- ASCII A-label form, lower-cased. The canonical value.
    Name                      NVARCHAR(253)    NOT NULL,

    -- Unicode U-label form for display.
    UnicodeName               NVARCHAR(253)    NOT NULL,

    -- DomainStatus: 0 Pending, 1 Active, 2 Disabled, 3 PendingDeletion.
    Status                    INT              NOT NULL CONSTRAINT DF_Domains_Status DEFAULT (0),

    MailHostname              NVARCHAR(253)    NULL,
    ActiveDkimSelector        NVARCHAR(63)     NULL,

    -- CatchAllPolicy: 0 Reject, 1 DeliverToCatchAll, 2 Discard.
    CatchAllPolicy            INT              NOT NULL CONSTRAINT DF_Domains_CatchAll DEFAULT (0),
    CatchAllMailbox           NVARCHAR(254)    NULL,

    -- Quotas in bytes; 0 means unlimited.
    DefaultMailboxQuotaBytes  BIGINT           NOT NULL CONSTRAINT DF_Domains_MbxQuota DEFAULT (0),
    DomainQuotaBytes          BIGINT           NOT NULL CONSTRAINT DF_Domains_DomQuota DEFAULT (0),

    MaxMessageSizeBytes       BIGINT           NOT NULL CONSTRAINT DF_Domains_MaxSize DEFAULT (36700160),
    RequireTlsForOutbound     BIT              NOT NULL CONSTRAINT DF_Domains_ReqTls DEFAULT (0),

    CreatedUtc                DATETIMEOFFSET(7) NOT NULL,
    ModifiedUtc               DATETIMEOFFSET(7) NULL,

    -- NONCLUSTERED primary key. The clustered index is on Name instead (below), because
    -- domains are overwhelmingly looked up and listed by name, and clustering on a GUID
    -- would scatter inserts across the B-tree for no read benefit.
    CONSTRAINT PK_Domains PRIMARY KEY NONCLUSTERED (Id),

    CONSTRAINT CK_Domains_Status
        CHECK (Status BETWEEN 0 AND 3),
    CONSTRAINT CK_Domains_CatchAllPolicy
        CHECK (CatchAllPolicy BETWEEN 0 AND 2),
    CONSTRAINT CK_Domains_Quotas
        CHECK (DefaultMailboxQuotaBytes >= 0 AND DomainQuotaBytes >= 0),
    CONSTRAINT CK_Domains_MaxMessageSize
        CHECK (MaxMessageSizeBytes >= 65536),

    -- Matches the SQLite constraint exactly: a catch-all destination is meaningless
    -- unless the policy selects it, and the policy cannot be selected without one.
    CONSTRAINT CK_Domains_CatchAllMailbox
        CHECK ((CatchAllPolicy = 1 AND CatchAllMailbox IS NOT NULL)
            OR (CatchAllPolicy <> 1 AND CatchAllMailbox IS NULL))
);
GO

-- Clustered and unique: every inbound RCPT TO resolves its recipient domain here.
CREATE UNIQUE CLUSTERED INDEX UX_Domains_Name ON dbo.Domains (Name);
GO

-- Covers the SMTP hot path's "which domains are we accepting mail for" lookup without
-- touching the clustered index.
CREATE NONCLUSTERED INDEX IX_Domains_Status
    ON dbo.Domains (Status)
    INCLUDE (Name, MailHostname, ActiveDkimSelector, MaxMessageSizeBytes);
GO


-- -----------------------------------------------------------------------------
-- Mailboxes: the addresses that receive mail.
-- Credentials, folders, forwarding and aliases arrive with Milestone 5.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.Mailboxes (
    Id                   UNIQUEIDENTIFIER  NOT NULL,
    DomainId             UNIQUEIDENTIFIER  NOT NULL,

    LocalPart            NVARCHAR(64)      NOT NULL,

    -- Normalised full address: the lookup and uniqueness key.
    Address              NVARCHAR(254)     NOT NULL,

    DisplayName          NVARCHAR(256)     NULL,

    -- 0 Disabled, 1 Active, 2 Suspended.
    Status               INT               NOT NULL CONSTRAINT DF_Mailboxes_Status DEFAULT (1),

    QuotaBytes           BIGINT            NOT NULL CONSTRAINT DF_Mailboxes_Quota DEFAULT (0),
    StorageUsedBytes     BIGINT            NOT NULL CONSTRAINT DF_Mailboxes_Used DEFAULT (0),
    MaxMessageSizeBytes  BIGINT            NOT NULL CONSTRAINT DF_Mailboxes_MaxSize DEFAULT (0),

    ImapEnabled          BIT               NOT NULL CONSTRAINT DF_Mailboxes_Imap DEFAULT (1),
    Pop3Enabled          BIT               NOT NULL CONSTRAINT DF_Mailboxes_Pop3 DEFAULT (0),
    SubmissionEnabled    BIT               NOT NULL CONSTRAINT DF_Mailboxes_Submit DEFAULT (1),

    CreatedUtc           DATETIMEOFFSET(7) NOT NULL,
    ModifiedUtc          DATETIMEOFFSET(7) NULL,
    LastLoginUtc         DATETIMEOFFSET(7) NULL,

    CONSTRAINT PK_Mailboxes PRIMARY KEY NONCLUSTERED (Id),

    -- NO ACTION (SQL Server's RESTRICT). Cascading a domain delete would remove mailbox
    -- rows while leaving every .eml file on disk unreferenced: unreclaimable storage and
    -- unrecoverable mail. Deletion must be an explicit, ordered operation.
    CONSTRAINT FK_Mailboxes_Domains
        FOREIGN KEY (DomainId) REFERENCES dbo.Domains (Id) ON DELETE NO ACTION,

    CONSTRAINT CK_Mailboxes_Status
        CHECK (Status BETWEEN 0 AND 2),
    CONSTRAINT CK_Mailboxes_Quota
        CHECK (QuotaBytes >= 0 AND StorageUsedBytes >= 0 AND MaxMessageSizeBytes >= 0)
);
GO

-- Clustered and unique: resolves a recipient on every RCPT TO and every login.
CREATE UNIQUE CLUSTERED INDEX UX_Mailboxes_Address ON dbo.Mailboxes (Address);
GO

-- Serves the per-domain count and storage aggregate on the domains grid entirely from
-- the index, with no lookups into the base table.
CREATE NONCLUSTERED INDEX IX_Mailboxes_DomainId
    ON dbo.Mailboxes (DomainId)
    INCLUDE (StorageUsedBytes, Status);
GO


-- -----------------------------------------------------------------------------
-- AuditRecords: append-only trail of privileged administrative actions.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.AuditRecords (
    Id                UNIQUEIDENTIFIER  NOT NULL,
    TimestampUtc      DATETIMEOFFSET(7) NOT NULL,
    Administrator     NVARCHAR(256)     NOT NULL,
    Action            NVARCHAR(128)     NOT NULL,
    TargetType        NVARCHAR(128)     NOT NULL,
    TargetIdentifier  NVARCHAR(512)     NULL,

    -- AuditResult: 0 Success, 1 Failure, 2 Denied.
    Result            INT               NOT NULL,

    Detail            NVARCHAR(1024)    NULL,
    MachineName       NVARCHAR(256)     NOT NULL,
    SessionIdentifier NVARCHAR(128)     NULL,
    CorrelationId     NVARCHAR(64)      NOT NULL,

    CONSTRAINT PK_AuditRecords PRIMARY KEY NONCLUSTERED (Id),
    CONSTRAINT CK_AuditRecords_Result CHECK (Result BETWEEN 0 AND 2)
);
GO

-- Clustered on time: this table is append-only and almost always read newest-first, so
-- clustering on the insert order keeps writes sequential and range scans cheap.
CREATE CLUSTERED INDEX IX_AuditRecords_TimestampUtc
    ON dbo.AuditRecords (TimestampUtc DESC);
GO

CREATE NONCLUSTERED INDEX IX_AuditRecords_CorrelationId
    ON dbo.AuditRecords (CorrelationId);
GO

CREATE NONCLUSTERED INDEX IX_AuditRecords_Action
    ON dbo.AuditRecords (Action, TimestampUtc DESC);
GO


-- -----------------------------------------------------------------------------
-- ServerSettings: small mutable runtime state that must survive a restart.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.ServerSettings (
    SettingKey   NVARCHAR(128)     NOT NULL,
    SettingValue NVARCHAR(MAX)     NOT NULL,
    ModifiedUtc  DATETIMEOFFSET(7) NOT NULL,

    CONSTRAINT PK_ServerSettings PRIMARY KEY CLUSTERED (SettingKey)
);
GO
