-- =============================================================================
-- AetherMail Server - submission rate limiting (SQLite)
-- Milestone 7
--
-- One index. Purely additive, no data rewritten, no destructive directive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- The per-mailbox submission rate limit counts what one authenticated mailbox has
-- had accepted in the last hour. That query runs on the SUBMISSION PATH, once per
-- MAIL FROM, so it cannot be a scan of every message the server has ever received.
--
-- Filtered to authenticated messages only. Mail from the Internet has no
-- AuthenticatedAs, and on a busy server that is the overwhelming majority of rows;
-- indexing them would triple the index for entries no submission query will ever
-- look at.
-- -----------------------------------------------------------------------------
CREATE INDEX IX_Messages_Submission_Rate
    ON Messages (AuthenticatedAs, ReceivedUtc)
    WHERE AuthenticatedAs IS NOT NULL;
