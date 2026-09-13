-- =============================================================================
-- AetherMail Server - initial schema (SQLite)
-- Milestone 1: Core Foundation
--
-- Conventions used throughout the SQLite schema:
--   * GUIDs are stored as TEXT. Microsoft.Data.Sqlite round-trips System.Guid to and
--     from the 36-character "D" form, and TEXT keeps the data legible to sqlite3 for
--     support and forensics. SQLite has no fixed-width binary advantage to give up here.
--   * DateTimeOffset is stored as TEXT in ISO-8601 with offset, which is what
--     Microsoft.Data.Sqlite writes and reads. Every value is UTC.
--   * Booleans are INTEGER 0/1.
--   * Enums are INTEGER, matching the numeric values pinned in the Domain layer's enums.
--
-- Foreign keys must be enabled per connection (PRAGMA foreign_keys = ON); the
-- connection factory does this on every connection it opens.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- Domains: the mail domains this server hosts.
-- -----------------------------------------------------------------------------
CREATE TABLE Domains (
    Id                        TEXT    NOT NULL PRIMARY KEY,

    -- ASCII A-label form, lower-cased. The canonical value: DNS lookups, envelope
    -- matching and every unique constraint use this and never the Unicode form.
    Name                      TEXT    NOT NULL,

    -- Unicode U-label form for display. Equal to Name for non-IDN domains.
    UnicodeName               TEXT    NOT NULL,

    -- DomainStatus: 0 Pending, 1 Active, 2 Disabled, 3 PendingDeletion.
    Status                    INTEGER NOT NULL DEFAULT 0,

    -- Outbound identity (EHLO name, MX target, TLS certificate SAN).
    MailHostname              TEXT    NULL,

    ActiveDkimSelector        TEXT    NULL,

    -- CatchAllPolicy: 0 Reject, 1 DeliverToCatchAll, 2 Discard.
    CatchAllPolicy            INTEGER NOT NULL DEFAULT 0,
    CatchAllMailbox           TEXT    NULL,

    -- Quotas in bytes; 0 means unlimited.
    DefaultMailboxQuotaBytes  INTEGER NOT NULL DEFAULT 0,
    DomainQuotaBytes          INTEGER NOT NULL DEFAULT 0,

    MaxMessageSizeBytes       INTEGER NOT NULL DEFAULT 36700160,
    RequireTlsForOutbound     INTEGER NOT NULL DEFAULT 0,

    CreatedUtc                TEXT    NOT NULL,
    ModifiedUtc               TEXT    NULL,

    CONSTRAINT CK_Domains_Status
        CHECK (Status BETWEEN 0 AND 3),
    CONSTRAINT CK_Domains_CatchAllPolicy
        CHECK (CatchAllPolicy BETWEEN 0 AND 2),
    CONSTRAINT CK_Domains_Quotas
        CHECK (DefaultMailboxQuotaBytes >= 0 AND DomainQuotaBytes >= 0),
    CONSTRAINT CK_Domains_MaxMessageSize
        CHECK (MaxMessageSizeBytes >= 65536),

    -- A catch-all destination is meaningless unless the policy selects it, and the
    -- policy cannot be selected without one. Enforced in the aggregate AND here:
    -- the aggregate gives the good error message, the constraint guarantees the rule
    -- under concurrency and against any future code path that bypasses the aggregate.
    CONSTRAINT CK_Domains_CatchAllMailbox
        CHECK ((CatchAllPolicy = 1 AND CatchAllMailbox IS NOT NULL)
            OR (CatchAllPolicy <> 1 AND CatchAllMailbox IS NULL))
);

-- The single most important index in the schema: every inbound RCPT TO resolves a
-- recipient domain through it. UNIQUE because hosting the same domain twice would make
-- delivery routing non-deterministic.
CREATE UNIQUE INDEX UX_Domains_Name ON Domains (Name);

-- Supports the SMTP hot path's "which domains are we accepting mail for" lookup.
CREATE INDEX IX_Domains_Status ON Domains (Status);


-- -----------------------------------------------------------------------------
-- Mailboxes: the addresses that receive mail.
--
-- Milestone 1 creates this table because domain deletion must refuse to orphan
-- mailboxes, and the domain grid shows per-domain mailbox counts and storage.
-- Credentials, folders, forwarding and aliases arrive with Milestone 5.
-- -----------------------------------------------------------------------------
CREATE TABLE Mailboxes (
    Id                   TEXT    NOT NULL PRIMARY KEY,
    DomainId             TEXT    NOT NULL,

    -- The local-part exactly as the administrator entered it, for display.
    LocalPart            TEXT    NOT NULL,

    -- Full address, normalised (lower-cased local-part, ASCII domain). This is the
    -- lookup and uniqueness key; see EmailAddress.NormalizedValue for the rationale.
    Address              TEXT    NOT NULL,

    DisplayName          TEXT    NULL,

    -- 0 Disabled, 1 Active, 2 Suspended.
    Status               INTEGER NOT NULL DEFAULT 1,

    -- 0 means inherit the domain default.
    QuotaBytes           INTEGER NOT NULL DEFAULT 0,
    StorageUsedBytes     INTEGER NOT NULL DEFAULT 0,

    -- 0 means inherit the domain default.
    MaxMessageSizeBytes  INTEGER NOT NULL DEFAULT 0,

    ImapEnabled          INTEGER NOT NULL DEFAULT 1,
    Pop3Enabled          INTEGER NOT NULL DEFAULT 0,
    SubmissionEnabled    INTEGER NOT NULL DEFAULT 1,

    CreatedUtc           TEXT    NOT NULL,
    ModifiedUtc          TEXT    NULL,
    LastLoginUtc         TEXT    NULL,

    -- RESTRICT, not CASCADE. Cascading a domain delete would remove mailbox rows while
    -- leaving every .eml file on disk with nothing referencing it: unreclaimable
    -- storage and unrecoverable mail. Deletion must be an explicit, ordered operation.
    CONSTRAINT FK_Mailboxes_Domains
        FOREIGN KEY (DomainId) REFERENCES Domains (Id) ON DELETE RESTRICT,

    CONSTRAINT CK_Mailboxes_Status
        CHECK (Status BETWEEN 0 AND 2),
    CONSTRAINT CK_Mailboxes_Quota
        CHECK (QuotaBytes >= 0 AND StorageUsedBytes >= 0 AND MaxMessageSizeBytes >= 0)
);

-- Resolves a recipient address on every RCPT TO and every IMAP/submission login.
CREATE UNIQUE INDEX UX_Mailboxes_Address ON Mailboxes (Address);

-- Serves the per-domain count and storage aggregate on the domains grid.
CREATE INDEX IX_Mailboxes_DomainId ON Mailboxes (DomainId);


-- -----------------------------------------------------------------------------
-- AuditRecords: append-only trail of privileged administrative actions.
--
-- There is no UPDATE or DELETE against this table anywhere in the product.
-- Secrets are never written here: the record's Detail comes from the request's own
-- hand-written AuditDescriptor, never from serialising the request object.
-- -----------------------------------------------------------------------------
CREATE TABLE AuditRecords (
    Id                TEXT    NOT NULL PRIMARY KEY,
    TimestampUtc      TEXT    NOT NULL,
    Administrator     TEXT    NOT NULL,
    Action            TEXT    NOT NULL,
    TargetType        TEXT    NOT NULL,
    TargetIdentifier  TEXT    NULL,

    -- AuditResult: 0 Success, 1 Failure, 2 Denied.
    Result            INTEGER NOT NULL,

    Detail            TEXT    NULL,
    MachineName       TEXT    NOT NULL,
    SessionIdentifier TEXT    NULL,
    CorrelationId     TEXT    NOT NULL,

    CONSTRAINT CK_AuditRecords_Result CHECK (Result BETWEEN 0 AND 2)
);

-- The audit viewer is almost always "most recent first".
CREATE INDEX IX_AuditRecords_TimestampUtc ON AuditRecords (TimestampUtc DESC);

-- "What else happened as part of this operation?" - joins the audit trail to the
-- structured log and, from Milestone 8, to message traces.
CREATE INDEX IX_AuditRecords_CorrelationId ON AuditRecords (CorrelationId);

-- "Show me every certificate renewal" / "every password reset".
CREATE INDEX IX_AuditRecords_Action ON AuditRecords (Action, TimestampUtc DESC);


-- -----------------------------------------------------------------------------
-- ServerSettings: small mutable runtime state that must survive a restart.
--
-- Deliberately key/value rather than a wide singleton row. The values here are
-- operational state (current maintenance mode, first-run completion) rather than
-- configuration - configuration lives in appsettings and the protected secret store.
-- -----------------------------------------------------------------------------
CREATE TABLE ServerSettings (
    SettingKey   TEXT NOT NULL PRIMARY KEY,
    SettingValue TEXT NOT NULL,
    ModifiedUtc  TEXT NOT NULL
);
