-- =============================================================================
-- AetherMail Server - DMARC verification results (SQLite)
-- Milestone 9
--
-- Purely additive: one new table and its index. No existing table is altered,
-- so this carries no destructive directive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- DmarcVerificationResults: the outcome of evaluating DMARC alignment for one
-- received message.
--
-- One row per message, unlike DkimVerificationResults' one row per signature -
-- DMARC alignment is a single verdict computed from every DKIM signature and
-- the one SPF result together. Never a mutation of the stored message: see
-- DkimVerificationResults' own remarks.
-- -----------------------------------------------------------------------------
CREATE TABLE DmarcVerificationResults (
    Id                TEXT    NOT NULL PRIMARY KEY,
    MessageId         TEXT    NOT NULL,

    -- DmarcResult: 0 Fail, 1 Pass. NULL means DMARC did not apply to this
    -- message at all (no usable From: header, or no policy published
    -- anywhere along the discovery chain) - distinct from a Fail, where a
    -- policy was found and evaluated but neither mechanism aligned.
    Result            INTEGER NULL,

    -- DmarcPolicy actually requested for this message, after sp=/p=
    -- resolution and pct= sampling: 0 None, 1 Quarantine, 2 Reject.
    Disposition       INTEGER NOT NULL,

    -- DmarcAlignedMechanism flags: 0 None, 1 Spf, 2 Dkim, 3 both.
    AlignedMechanisms INTEGER NOT NULL,

    FromDomain        TEXT    NULL,
    PolicyDomain      TEXT    NULL,
    Diagnostic        TEXT    NULL,

    CreatedUtc        TEXT    NOT NULL,

    CONSTRAINT FK_DmarcVerificationResults_Message
        FOREIGN KEY (MessageId) REFERENCES Messages (Id) ON DELETE CASCADE,

    CONSTRAINT CK_DmarcVerificationResults_Result CHECK (Result BETWEEN 0 AND 1),
    CONSTRAINT CK_DmarcVerificationResults_Disposition CHECK (Disposition BETWEEN 0 AND 2),
    CONSTRAINT CK_DmarcVerificationResults_AlignedMechanisms CHECK (AlignedMechanisms BETWEEN 0 AND 3)
) STRICT;

-- A future Authentication-Results composition step reads this alongside a
-- message's DkimVerificationResults rows.
CREATE INDEX IX_DmarcVerificationResults_MessageId
    ON DmarcVerificationResults (MessageId);
