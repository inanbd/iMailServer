-- =============================================================================
-- AetherMail Server - security and administration (Microsoft SQL Server)
-- Milestone 2
--
-- The SQL Server counterpart of the SQLite 0002 script. The two are kept deliberately
-- in step; anything that cannot be expressed identically is called out in a comment
-- rather than allowed to diverge silently.
--
-- Purely additive: no existing table is altered, so this is not marked @Destructive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- AdminAccounts: the identity that guards the administration console.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.AdminAccounts (
    Id                  UNIQUEIDENTIFIER  NOT NULL,
    Name                NVARCHAR(256)     NOT NULL,

    -- Argon2id verifier in PHC string format. The work factors travel with the hash,
    -- so raising them later does not invalidate existing passwords; an old hash is
    -- upgraded on the next successful sign-in.
    PasswordHash        NVARCHAR(1024)    NOT NULL,

    -- Hashed, not encrypted: the recovery key grants full control of the server, so a
    -- database dump must not yield it. NULL once consumed.
    RecoveryKeyHash     NVARCHAR(1024)    NULL,

    Permissions         INT               NOT NULL CONSTRAINT DF_AdminAccounts_Perms DEFAULT (0),

    -- Persisted, not in memory: a counter that reset on service restart would be no
    -- lockout at all.
    ConsecutiveFailures INT               NOT NULL CONSTRAINT DF_AdminAccounts_Fails DEFAULT (0),
    LastFailureUtc      DATETIMEOFFSET(7) NULL,
    LockedOutUntilUtc   DATETIMEOFFSET(7) NULL,

    LastSignInUtc       DATETIMEOFFSET(7) NULL,
    MustChangePassword  BIT               NOT NULL CONSTRAINT DF_AdminAccounts_MustChg DEFAULT (0),

    CreatedUtc          DATETIMEOFFSET(7) NOT NULL,
    PasswordChangedUtc  DATETIMEOFFSET(7) NULL,

    CONSTRAINT PK_AdminAccounts PRIMARY KEY NONCLUSTERED (Id),
    CONSTRAINT CK_AdminAccounts_Failures CHECK (ConsecutiveFailures >= 0)
);
GO

-- Clustered and unique on Name: every sign-in resolves the account this way, and the
-- uniqueness is what decides the winner when two clients race to complete setup.
CREATE UNIQUE CLUSTERED INDEX UX_AdminAccounts_Name ON dbo.AdminAccounts (Name);
GO


-- -----------------------------------------------------------------------------
-- SecurityEvents: what happened to the security posture.
--
-- Separate from AuditRecords: written out of band so that it survives the rollback of
-- a failing operation, and produced in far higher volume. See the SQLite counterpart
-- for the full reasoning.
--
-- NEVER contains a credential.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.SecurityEvents (
    Id            UNIQUEIDENTIFIER  NOT NULL,
    TimestampUtc  DATETIMEOFFSET(7) NOT NULL,
    EventType     INT               NOT NULL,

    -- NULL for a failure against an account that does not exist. The attempted name is
    -- deliberately not stored: it is attacker-controlled text destined for an admin UI.
    Subject       NVARCHAR(256)     NULL,
    Origin        NVARCHAR(256)     NULL,

    Description   NVARCHAR(1024)    NOT NULL,
    MachineName   NVARCHAR(256)     NOT NULL,
    CorrelationId NVARCHAR(64)      NOT NULL,

    IsAlarming    BIT               NOT NULL CONSTRAINT DF_SecurityEvents_Alarm DEFAULT (0),

    CONSTRAINT PK_SecurityEvents PRIMARY KEY NONCLUSTERED (Id)
);
GO

-- Clustered on time: append-only and read newest-first, so writes stay sequential and
-- range scans stay cheap. Same choice as AuditRecords, for the same reasons.
CREATE CLUSTERED INDEX IX_SecurityEvents_TimestampUtc
    ON dbo.SecurityEvents (TimestampUtc DESC);
GO

-- Serves the failed-sign-in counter on the security overview without a base-table
-- lookup.
CREATE NONCLUSTERED INDEX IX_SecurityEvents_EventType
    ON dbo.SecurityEvents (EventType, TimestampUtc DESC)
    INCLUDE (Subject, Origin);
GO

-- "Show me only what matters", the default view during an incident. Filtered, so the
-- index stays small: alarming events are a tiny fraction of the table.
CREATE NONCLUSTERED INDEX IX_SecurityEvents_Alarming
    ON dbo.SecurityEvents (TimestampUtc DESC)
    WHERE IsAlarming = 1;
GO

CREATE NONCLUSTERED INDEX IX_SecurityEvents_CorrelationId
    ON dbo.SecurityEvents (CorrelationId);
GO


-- -----------------------------------------------------------------------------
-- ProtectedSecrets: values the server must be able to read back.
--
-- ProtectedValue arrives ALREADY ENCRYPTED from ISecretProtector. DPAPI is
-- machine-scoped, so this table is not portable between machines; restoring onto
-- different hardware requires the backup passphrase (docs/BackupRestore.md).
--
-- Passwords never appear here - they are hashed in AdminAccounts instead.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.ProtectedSecrets (
    SecretName       NVARCHAR(256)     NOT NULL,
    ProtectedValue   NVARCHAR(MAX)     NOT NULL,
    Description      NVARCHAR(512)     NULL,
    ProtectionScheme NVARCHAR(64)      NOT NULL,
    CreatedUtc       DATETIMEOFFSET(7) NOT NULL,
    ModifiedUtc      DATETIMEOFFSET(7) NULL,

    CONSTRAINT PK_ProtectedSecrets PRIMARY KEY CLUSTERED (SecretName)
);
GO
