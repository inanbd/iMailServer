-- =============================================================================
-- AetherMail Server - outbound queue and delivery attempt history (Microsoft SQL Server)
-- Milestone 8
--
-- The SQL Server counterpart of the SQLite 0008 script, kept deliberately in
-- step. Purely additive: two new tables and their indexes. No existing table
-- is altered, so this carries no destructive directive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- OutboundQueueItems: one row per RECIPIENT of one message still to be relayed
-- onward, not one row per message. See the SQLite script for the full rationale;
-- kept here only where the SQL Server spelling differs.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.OutboundQueueItems (
    Id                  UNIQUEIDENTIFIER  NOT NULL,
    MessageId           UNIQUEIDENTIFIER  NOT NULL,
    RecipientId         UNIQUEIDENTIFIER  NOT NULL,

    DestinationAddress  NVARCHAR(320)     NOT NULL,
    DestinationDomain   NVARCHAR(253)     NOT NULL,

    -- NULL is the null reverse path. A queue item with a null reverse path must
    -- never generate a DSN on failure - see OutboundQueueItem.ShouldGenerateDsnOnFailure.
    ReversePath         NVARCHAR(320)     NULL,

    -- A snapshot of MailDomain.RequireTlsForOutbound taken when this item was
    -- enqueued, so a later policy change cannot silently alter a message already
    -- in flight.
    RequireTls          BIT               NOT NULL CONSTRAINT DF_OutboundQueueItems_RequireTls DEFAULT (0),

    -- True when this item carries a DSN this server generated rather than a
    -- relayed message.
    IsDsn               BIT               NOT NULL CONSTRAINT DF_OutboundQueueItems_IsDsn DEFAULT (0),

    -- Lower claims first. DSNs get -1 so a bounce is not stuck behind an
    -- ordinary backlog.
    Priority            INT               NOT NULL CONSTRAINT DF_OutboundQueueItems_Priority DEFAULT (0),

    -- QueueStatus: 0 Pending, 1 Processing, 2 Deferred, 3 Delivered, 4 Bounced,
    -- 5 Cancelled.
    Status              INT               NOT NULL CONSTRAINT DF_OutboundQueueItems_Status DEFAULT (0),

    AttemptCount        INT               NOT NULL CONSTRAINT DF_OutboundQueueItems_AttemptCount DEFAULT (0),

    FirstQueuedUtc      DATETIMEOFFSET(7) NOT NULL,
    NextAttemptUtc      DATETIMEOFFSET(7) NOT NULL,

    -- Leasing, not locking. See the SQLite script's remarks; the mechanism is
    -- identical, only the claim statement's syntax differs (READPAST/UPDLOCK
    -- below rather than UPDATE ... RETURNING).
    LeaseOwner          NVARCHAR(128)     NULL,
    LeaseExpiresUtc     DATETIMEOFFSET(7) NULL,

    DelayWarningSentUtc DATETIMEOFFSET(7) NULL,
    LastFailureReason   NVARCHAR(1024)    NULL,

    CreatedUtc          DATETIMEOFFSET(7) NOT NULL,
    ModifiedUtc         DATETIMEOFFSET(7) NOT NULL,

    CONSTRAINT PK_OutboundQueueItems PRIMARY KEY CLUSTERED (Id),

    CONSTRAINT FK_OutboundQueueItems_Message
        FOREIGN KEY (MessageId) REFERENCES dbo.Messages (Id) ON DELETE NO ACTION,

    CONSTRAINT FK_OutboundQueueItems_Recipient
        FOREIGN KEY (RecipientId) REFERENCES dbo.MessageRecipients (Id) ON DELETE NO ACTION,

    CONSTRAINT CK_OutboundQueueItems_Status CHECK (Status BETWEEN 0 AND 5)
);
GO

-- The scheduler's own query: due items ready to claim, in priority then age
-- order. Filtered, because only Pending and Deferred rows are ever "due" - a
-- Processing row is found by IX_OutboundQueueItems_Lease below instead.
CREATE INDEX IX_OutboundQueueItems_Due
    ON dbo.OutboundQueueItems (Priority, NextAttemptUtc)
    WHERE (Status = 0 OR Status = 2);
GO

-- Reclaiming a crashed worker's expired leases.
CREATE INDEX IX_OutboundQueueItems_Lease
    ON dbo.OutboundQueueItems (LeaseExpiresUtc)
    WHERE (Status = 1);
GO

-- Per-domain grouping, for the per-domain throttle and the admin queue grid.
CREATE INDEX IX_OutboundQueueItems_Domain ON dbo.OutboundQueueItems (DestinationDomain, Status);
GO

CREATE INDEX IX_OutboundQueueItems_MessageId ON dbo.OutboundQueueItems (MessageId);
GO


-- -----------------------------------------------------------------------------
-- DeliveryAttempts: the full record of one attempt against one queue item. See
-- the SQLite script for the full rationale.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.DeliveryAttempts (
    Id                     UNIQUEIDENTIFIER  NOT NULL,
    QueueItemId            UNIQUEIDENTIFIER  NOT NULL,
    AttemptNumber          INT               NOT NULL,

    StartedUtc             DATETIMEOFFSET(7) NOT NULL,
    CompletedUtc           DATETIMEOFFSET(7) NOT NULL,

    MxHostname             NVARCHAR(255)     NULL,
    RemoteAddress          NVARCHAR(45)      NULL,

    TlsActive              BIT               NOT NULL CONSTRAINT DF_DeliveryAttempts_TlsActive DEFAULT (0),
    TlsProtocol            NVARCHAR(32)      NULL,
    TlsCipher              NVARCHAR(64)      NULL,
    PeerCertificateSubject NVARCHAR(512)     NULL,
    PeerCertificateIssuer  NVARCHAR(512)     NULL,

    ReplyCode              INT               NULL,
    EnhancedStatus         NVARCHAR(16)      NULL,
    ReplyText              NVARCHAR(1024)    NULL,

    -- DeliveryOutcome: 0 Delivered, 1 Deferred, 2 Bounced, 3 TlsRequiredFailure,
    -- 4 Cancelled.
    Outcome                INT               NOT NULL,

    -- FailureClassification: 0 None, 1 Temporary, 2 Permanent.
    FailureClassification  INT               NOT NULL,

    ErrorDetail            NVARCHAR(1024)    NULL,

    CreatedUtc             DATETIMEOFFSET(7) NOT NULL,

    CONSTRAINT PK_DeliveryAttempts PRIMARY KEY CLUSTERED (Id),

    CONSTRAINT FK_DeliveryAttempts_QueueItem
        FOREIGN KEY (QueueItemId) REFERENCES dbo.OutboundQueueItems (Id) ON DELETE CASCADE
);
GO

-- The trace view for one queue item, in attempt order.
CREATE INDEX IX_DeliveryAttempts_QueueItemId ON dbo.DeliveryAttempts (QueueItemId, AttemptNumber);
GO
