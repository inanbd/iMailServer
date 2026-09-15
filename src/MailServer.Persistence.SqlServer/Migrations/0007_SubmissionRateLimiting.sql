-- =============================================================================
-- AetherMail Server - submission rate limiting (Microsoft SQL Server)
-- Milestone 7
--
-- The SQL Server counterpart of the SQLite 0007 script. One index, purely
-- additive, no destructive directive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- The per-mailbox submission rate limit runs on the SUBMISSION PATH, once per
-- MAIL FROM, so it cannot be a scan of every message the server has ever received.
--
-- Filtered to authenticated messages only, which is the SQL Server spelling of
-- SQLite's partial index and the same intent: mail from the Internet has no
-- AuthenticatedAs, and on a busy server that is most rows.
-- -----------------------------------------------------------------------------
CREATE INDEX IX_Messages_Submission_Rate
    ON dbo.Messages (AuthenticatedAs, ReceivedUtc)
    WHERE AuthenticatedAs IS NOT NULL;
GO
