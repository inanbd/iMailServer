-- =============================================================================
-- AetherMail Server - ACME / Let's Encrypt (Microsoft SQL Server)
-- Milestone 4
--
-- The SQL Server counterpart of the SQLite 0004 script. The two are kept
-- deliberately in step; anything that cannot be expressed identically is called
-- out in a comment rather than allowed to diverge silently.
--
-- Purely additive: no existing table is altered, so this carries no destructive
-- directive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- AcmeAccounts: a registration with a certificate authority.
--
-- No key material: the account key lives in ProtectedSecrets, DPAPI-encrypted,
-- and this table carries only the NAME of that secret.
--
-- Rows are never deleted. Revoking a certificate needs the account key that
-- issued it, so discarding a deactivated account strips the ability to revoke
-- everything it ever issued.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.AcmeAccounts (
    Id                   UNIQUEIDENTIFIER  NOT NULL,

    -- AcmeDirectory: 0 LetsEncryptStaging, 1 LetsEncryptProduction, 2 Custom.
    Directory            INT               NOT NULL,

    DirectoryUrl         NVARCHAR(512)     NOT NULL,

    -- NULL means registration was started and not completed, which is
    -- recoverable: the key is reused and registration retried.
    AccountUrl           NVARCHAR(512)     NULL,

    ContactEmail         NVARCHAR(320)     NOT NULL,

    -- The NAME of the secret holding the account key, never the key.
    AccountKeySecretName NVARCHAR(256)     NOT NULL,

    -- By URL rather than a boolean: CAs revise their terms and a later version
    -- may need accepting again.
    TermsAccepted        NVARCHAR(512)     NULL,
    TermsAcceptedUtc     DATETIMEOFFSET(7) NULL,

    IsActive             BIT               NOT NULL
        CONSTRAINT DF_AcmeAccounts_IsActive DEFAULT (1),

    CreatedUtc           DATETIMEOFFSET(7) NOT NULL,
    ModifiedUtc          DATETIMEOFFSET(7) NULL,

    CONSTRAINT PK_AcmeAccounts PRIMARY KEY NONCLUSTERED (Id)
);

-- One active account per directory. A filtered unique index is the SQL Server
-- spelling of SQLite's partial index. Two active accounts would make "which
-- account issued this certificate" depend on row order, and the account key is
-- what can later revoke it.
CREATE UNIQUE INDEX UX_AcmeAccounts_ActiveDirectory
    ON dbo.AcmeAccounts (Directory)
    WHERE IsActive = 1;


-- -----------------------------------------------------------------------------
-- AcmeOrders: one issuance attempt, from request to outcome.
--
-- Persisted because rate limiting needs history that survives a restart, manual
-- DNS-01 can take an operator an hour, and a failure a week ago is unanswerable
-- without the identifiers and the CA's own error text.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.AcmeOrders (
    Id                  UNIQUEIDENTIFIER  NOT NULL,
    AccountId           UNIQUEIDENTIFIER  NOT NULL,

    Identifiers         NVARCHAR(MAX)     NOT NULL,

    -- Sorted identifier set, for the CA's duplicate-certificate limit, which is
    -- on the SET. Bounded rather than MAX because it is indexed; 900 bytes is
    -- SQL Server's index key limit and NVARCHAR(400) stays inside it.
    IdentifierSetKey    NVARCHAR(400)     NOT NULL,

    RegisteredDomain    VARCHAR(255)      NOT NULL,

    -- AcmeChallengeType: 0 Http01, 1 Dns01.
    ChallengeType       INT               NOT NULL,

    -- AcmeOrderStatus: 0 Created … 7 Abandoned.
    Status              INT               NOT NULL,

    -- NULL means the CA never saw this order - what distinguishes a local
    -- refusal from a consumed quota slot.
    OrderUrl            NVARCHAR(512)     NULL,

    IssuedCertificateId UNIQUEIDENTIFIER  NULL,

    LastError           NVARCHAR(2048)    NULL,

    AttemptCount        INT               NOT NULL
        CONSTRAINT DF_AcmeOrders_AttemptCount DEFAULT (0),
    LastAttemptUtc      DATETIMEOFFSET(7) NULL,
    CompletedUtc        DATETIMEOFFSET(7) NULL,

    CreatedUtc          DATETIMEOFFSET(7) NOT NULL,
    ModifiedUtc         DATETIMEOFFSET(7) NULL,

    CONSTRAINT PK_AcmeOrders PRIMARY KEY NONCLUSTERED (Id),

    -- NO ACTION is SQL Server's RESTRICT.
    CONSTRAINT FK_AcmeOrders_Account
        FOREIGN KEY (AccountId) REFERENCES dbo.AcmeAccounts (Id) ON DELETE NO ACTION,

    -- SET NULL rather than CASCADE: deleting a certificate must not erase the
    -- record that it was once issued, because that record is rate-limit history.
    CONSTRAINT FK_AcmeOrders_Certificate
        FOREIGN KEY (IssuedCertificateId) REFERENCES dbo.Certificates (Id) ON DELETE SET NULL
);

-- Clustered on creation time: orders are written once, read in time windows by
-- the rate limiter, and never updated after they finish.
CREATE CLUSTERED INDEX IX_AcmeOrders_CreatedUtc ON dbo.AcmeOrders (CreatedUtc);

CREATE INDEX IX_AcmeOrders_SetKey_Attempt
    ON dbo.AcmeOrders (IdentifierSetKey, LastAttemptUtc);

CREATE INDEX IX_AcmeOrders_RegisteredDomain_Attempt
    ON dbo.AcmeOrders (RegisteredDomain, LastAttemptUtc);

CREATE INDEX IX_AcmeOrders_Status_Attempt
    ON dbo.AcmeOrders (Status, LastAttemptUtc);
