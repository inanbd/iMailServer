-- =============================================================================
-- AetherMail Server - collected TLS reports (SQLite)
-- Milestone 11
--
-- Purely additive: one new table and its indexes. Nothing existing is altered
-- or dropped, so this carries no destructive directive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- TlsReports: RFC 8460 reports other senders delivered to this domain's rua
-- address, after collection.
--
-- WHAT THESE ARE. A sender's own account of the TLS sessions it had with us
-- over a period: how many negotiated successfully, how many did not, and why.
-- It is the only feedback channel in this product that reports a real handshake
-- from a real sender - a certificate that validates perfectly on this host and
-- fails at Google is invisible to every local check and is exactly what a report
-- tells us.
--
-- WHY THE SUMMARY IS STORED RATHER THAN THE DOCUMENT. The failures are stored as
-- rows in TlsReportFailures below, grouped as the analysis groups them. Keeping
-- the raw JSON as well would mean storing somebody else's unbounded document
-- indefinitely for the sake of a re-parse nobody performs; the counts and the
-- result types are what an operator acts on, and they are what is kept.
--
-- THESE ROWS ARE CLAIMS, NOT FINDINGS. A report is unauthenticated: anyone who
-- can reach the rua address can send one, and nothing in RFC 8460 proves the
-- organisation named actually sent it. OrganizationName and ContactInfo are
-- therefore whatever the sender wrote, and are stored as such. Nothing in this
-- product may change a policy on the strength of one report.
-- -----------------------------------------------------------------------------
CREATE TABLE TlsReports (
    Id                      TEXT    NOT NULL PRIMARY KEY,

    -- The domain the report is about, as this server resolved it. Lower-cased
    -- by the collector so the unique index below folds case consistently on
    -- both providers rather than inheriting a collation.
    PolicyDomain            TEXT    NOT NULL,

    -- Everything the sender said about itself. Claims.
    OrganizationName        TEXT    NULL,
    ContactInfo             TEXT    NULL,
    ReportId                TEXT    NULL,

    -- The period the report covers, as the sender stated it.
    StartUtc                TEXT    NULL,
    EndUtc                  TEXT    NULL,

    SuccessfulSessionCount  INTEGER NOT NULL,
    FailedSessionCount      INTEGER NOT NULL,

    -- The one-sentence verdict, composed by TlsReport.Summarise at collection
    -- time. Stored rather than recomposed on read so that a listing does not
    -- have to rebuild every report to render a line, and so the wording an
    -- operator saw once does not change under them after an upgrade.
    Summary                 TEXT    NOT NULL,

    -- When this server collected it, not when the sender sent it.
    CollectedUtc            TEXT    NOT NULL,

    CONSTRAINT CK_TlsReports_SuccessfulSessionCount CHECK (SuccessfulSessionCount >= 0),
    CONSTRAINT CK_TlsReports_FailedSessionCount CHECK (FailedSessionCount >= 0)
) STRICT;

-- DE-DUPLICATION, and the reason collection can be re-run safely.
--
-- RFC 8460 4.1 makes report-id "a unique identifier for the report", and a
-- sender that retries a delivery sends the same id again. Without this, a
-- mailbox scanned twice would double every number an operator reads.
--
-- Scoped by domain and organisation because report-id is unique per sender
-- rather than globally: two senders may pick the same string, and folding their
-- reports together would attribute one's failures to the other.
--
-- A report with no id at all is not covered by this - SQLite treats NULLs as
-- distinct in a unique index - which is deliberate. Refusing such a report
-- would discard a real one; the collector's message-level tracking is what
-- keeps it from being read twice.
CREATE UNIQUE INDEX UX_TlsReports_Identity
    ON TlsReports (PolicyDomain, OrganizationName, ReportId)
    WHERE ReportId IS NOT NULL;

-- The listing is "the most recent reports for this domain".
CREATE INDEX IX_TlsReports_Domain_Collected
    ON TlsReports (PolicyDomain, CollectedUtc DESC);


-- -----------------------------------------------------------------------------
-- TlsReportFailures: one row per result type per report, already grouped.
--
-- WHY GROUPED RATHER THAN AS SENT. A sender reports per MX host and per sending
-- address, so one expired certificate arrives as a dozen entries that are all
-- the same problem. What an operator needs is which problem cost the most
-- sessions, which is the grouping TlsReport.FailuresByImpact performs. Storing
-- the ungrouped entries would mean re-deriving that on every read to answer the
-- only question anybody asks of them.
-- -----------------------------------------------------------------------------
CREATE TABLE TlsReportFailures (
    Id                  TEXT    NOT NULL PRIMARY KEY,
    TlsReportId         TEXT    NOT NULL,

    -- The RFC 8460 4.3 wire name, stored as text rather than as the enum's
    -- number. 4.3's list is extensible, and a type this version does not know
    -- is kept raw rather than folded into a catch-all - a number would lose it.
    ResultType          TEXT    NOT NULL,

    FailedSessionCount  INTEGER NOT NULL,

    -- The hosts of ours it happened on, comma-separated. A child table would be
    -- three rows of one short hostname each; this is read as a whole or not at
    -- all, and is never joined or filtered on.
    ReceivingMxHostnames TEXT   NULL,

    CONSTRAINT FK_TlsReportFailures_Report
        FOREIGN KEY (TlsReportId) REFERENCES TlsReports (Id) ON DELETE CASCADE,

    CONSTRAINT CK_TlsReportFailures_FailedSessionCount CHECK (FailedSessionCount >= 0)
) STRICT;

CREATE INDEX IX_TlsReportFailures_ReportId
    ON TlsReportFailures (TlsReportId);


-- -----------------------------------------------------------------------------
-- TlsReportSources: the messages already looked at.
--
-- WHY A TABLE RATHER THAN A FLAG ON THE MESSAGE. Marking the message \Seen
-- would be visible to a human reading the same mailbox and would be undone the
-- moment they marked it unread; deleting it would destroy evidence an operator
-- may want. This records the decision separately, so the mailbox is left exactly
-- as its owner left it.
--
-- FAILURES ARE RECORDED TOO, and that is the point of Error. A message that is
-- not a report - a bounce, a covering note, somebody's reply - must not be
-- re-examined on every pass forever, and an operator asking "why was this not
-- collected" needs the reason rather than silence.
-- -----------------------------------------------------------------------------
CREATE TABLE TlsReportSources (
    MessageId    TEXT    NOT NULL PRIMARY KEY,

    -- The report this message yielded, or NULL when it yielded none.
    TlsReportId  TEXT    NULL,

    -- Why it yielded none. NULL when it did.
    Error        TEXT    NULL,

    ExaminedUtc  TEXT    NOT NULL,

    CONSTRAINT FK_TlsReportSources_Message
        FOREIGN KEY (MessageId) REFERENCES Messages (Id) ON DELETE CASCADE,

    CONSTRAINT FK_TlsReportSources_Report
        FOREIGN KEY (TlsReportId) REFERENCES TlsReports (Id) ON DELETE SET NULL
) STRICT;
