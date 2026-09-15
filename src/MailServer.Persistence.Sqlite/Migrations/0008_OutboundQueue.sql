-- =============================================================================
-- AetherMail Server - outbound queue and delivery attempt history (SQLite)
-- Milestone 8
--
-- Purely additive: two new tables and their indexes. No existing table is
-- altered, so this carries no destructive directive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- OutboundQueueItems: one row per RECIPIENT of one message still to be relayed
-- onward, not one row per message.
--
-- A message to fifty recipients across a dozen domains must be able to succeed
-- for forty-nine of them and defer the fiftieth; a row per message could not
-- represent that. The message body itself is not here - it is the same file
-- Messages/{Id} already names, referenced by MessageId, exactly as a Delivery
-- references it for local mailboxes.
--
-- Envelope fields are copied from the MessageRecipients row that produced this
-- item rather than joined at read time: a worker claiming thousands of due
-- items reads this table alone.
-- -----------------------------------------------------------------------------
CREATE TABLE OutboundQueueItems (
    Id                  TEXT    NOT NULL PRIMARY KEY,
    MessageId           TEXT    NOT NULL,
    RecipientId         TEXT    NOT NULL,

    DestinationAddress  TEXT    NOT NULL,
    DestinationDomain   TEXT    NOT NULL,

    -- NULL is the null reverse path. A queue item with a null reverse path must
    -- never generate a DSN on failure - see OutboundQueueItem.ShouldGenerateDsnOnFailure.
    ReversePath         TEXT    NULL,

    -- A snapshot of MailDomain.RequireTlsForOutbound taken when this item was
    -- enqueued, so a later change to the domain's policy cannot silently alter
    -- what a message already in flight is held to.
    RequireTls          INTEGER NOT NULL DEFAULT 0,

    -- True when this item carries a DSN this server generated rather than a
    -- relayed message. Its own failure is still governed by ReversePath being
    -- NULL (which it always is for a DSN); this flag is for reporting.
    IsDsn               INTEGER NOT NULL DEFAULT 0,

    -- Lower claims first. DSNs get -1 so a bounce is not stuck behind an
    -- ordinary backlog.
    Priority            INTEGER NOT NULL DEFAULT 0,

    -- QueueStatus: 0 Pending, 1 Processing, 2 Deferred, 3 Delivered, 4 Bounced,
    -- 5 Cancelled.
    Status              INTEGER NOT NULL DEFAULT 0,

    AttemptCount        INTEGER NOT NULL DEFAULT 0,

    FirstQueuedUtc      TEXT    NOT NULL,
    NextAttemptUtc      TEXT    NOT NULL,

    -- Leasing, not locking. A worker claims by writing its own identity and an
    -- expiry here in the same atomic UPDATE that moves Status to Processing; a
    -- worker that crashes leaves a lease that simply expires and is reclaimed by
    -- whichever worker asks next. Nothing here assumes there is only ever one.
    LeaseOwner          TEXT    NULL,
    LeaseExpiresUtc     TEXT    NULL,

    DelayWarningSentUtc TEXT    NULL,
    LastFailureReason   TEXT    NULL,

    CreatedUtc          TEXT    NOT NULL,
    ModifiedUtc         TEXT    NOT NULL,

    CONSTRAINT FK_OutboundQueueItems_Message
        FOREIGN KEY (MessageId) REFERENCES Messages (Id) ON DELETE RESTRICT,

    CONSTRAINT FK_OutboundQueueItems_Recipient
        FOREIGN KEY (RecipientId) REFERENCES MessageRecipients (Id) ON DELETE RESTRICT,

    CONSTRAINT CK_OutboundQueueItems_Status CHECK (Status BETWEEN 0 AND 5)
) STRICT;

-- The scheduler's own query: due items ready to claim, in priority then age
-- order. Partial, because only Pending and Deferred rows are ever "due" - a
-- Processing row is found by IX_OutboundQueueItems_Lease below instead.
CREATE INDEX IX_OutboundQueueItems_Due
    ON OutboundQueueItems (Priority, NextAttemptUtc)
    WHERE Status IN (0, 2);

-- Reclaiming a crashed worker's expired leases.
CREATE INDEX IX_OutboundQueueItems_Lease
    ON OutboundQueueItems (LeaseExpiresUtc)
    WHERE Status = 1;

-- Per-domain grouping, for the per-domain throttle and the admin queue grid.
CREATE INDEX IX_OutboundQueueItems_Domain ON OutboundQueueItems (DestinationDomain, Status);

CREATE INDEX IX_OutboundQueueItems_MessageId ON OutboundQueueItems (MessageId);


-- -----------------------------------------------------------------------------
-- DeliveryAttempts: the full record of one attempt against one queue item.
--
-- Written once, after the SMTP conversation with the remote MX has finished,
-- never before - a row describing an attempt that never happened is worse than
-- no row, because it is evidence somebody will trust. Everything here exists to
-- answer "why did Gmail reject this?" months later: the MX hostname actually
-- connected to, the negotiated TLS version and cipher, the peer certificate's
-- subject and issuer whether or not it was trusted, and the remote's reply
-- verbatim.
-- -----------------------------------------------------------------------------
CREATE TABLE DeliveryAttempts (
    Id                     TEXT    NOT NULL PRIMARY KEY,
    QueueItemId            TEXT    NOT NULL,
    AttemptNumber          INTEGER NOT NULL,

    StartedUtc             TEXT    NOT NULL,
    CompletedUtc           TEXT    NOT NULL,

    MxHostname             TEXT    NULL,
    RemoteAddress          TEXT    NULL,

    TlsActive              INTEGER NOT NULL DEFAULT 0,
    TlsProtocol            TEXT    NULL,
    TlsCipher              TEXT    NULL,
    PeerCertificateSubject TEXT    NULL,
    PeerCertificateIssuer  TEXT    NULL,

    ReplyCode              INTEGER NULL,
    EnhancedStatus         TEXT    NULL,
    ReplyText              TEXT    NULL,

    -- DeliveryOutcome: 0 Delivered, 1 Deferred, 2 Bounced, 3 TlsRequiredFailure,
    -- 4 Cancelled.
    Outcome                INTEGER NOT NULL,

    -- FailureClassification: 0 None, 1 Temporary, 2 Permanent.
    FailureClassification  INTEGER NOT NULL,

    ErrorDetail            TEXT    NULL,

    CreatedUtc             TEXT    NOT NULL,

    CONSTRAINT FK_DeliveryAttempts_QueueItem
        FOREIGN KEY (QueueItemId) REFERENCES OutboundQueueItems (Id) ON DELETE CASCADE
) STRICT;

-- The trace view for one queue item, in attempt order.
CREATE INDEX IX_DeliveryAttempts_QueueItemId ON DeliveryAttempts (QueueItemId, AttemptNumber);
