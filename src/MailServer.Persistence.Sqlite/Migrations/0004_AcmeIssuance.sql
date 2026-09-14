-- =============================================================================
-- AetherMail Server - ACME / Let's Encrypt (SQLite)
-- Milestone 4
--
-- Adds the ACME account registration and the issuance-attempt history. Purely
-- additive: no existing table is altered, so this migration carries no
-- destructive directive and needs no pre-upgrade backup.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- AcmeAccounts: a registration with a certificate authority.
--
-- No key material. The account key lives in ProtectedSecrets, DPAPI-encrypted,
-- and this table carries only the NAME of that secret.
--
-- Staging and production are separate rows with separate keys. An account
-- registered against one directory is meaningless to the other, so the directory
-- is part of the row's identity rather than a setting to flip. Switching to
-- production registers a new account and KEEPS the staging one, which is what
-- lets an operator return to testing later.
--
-- Rows are never deleted. Revoking a certificate needs the account key that
-- issued it, so discarding a deactivated account strips the ability to revoke
-- everything it ever issued - precisely when that ability is most likely needed.
-- -----------------------------------------------------------------------------
CREATE TABLE AcmeAccounts (
    Id                   TEXT    NOT NULL PRIMARY KEY,

    -- AcmeDirectory: 0 LetsEncryptStaging, 1 LetsEncryptProduction, 2 Custom.
    Directory            INTEGER NOT NULL,

    DirectoryUrl         TEXT    NOT NULL,

    -- The account's URL at the CA, assigned on registration. NULL means the
    -- registration was started and not completed, which is recoverable: the key
    -- is reused and registration retried.
    AccountUrl           TEXT    NULL,

    -- Where the CA sends expiry warnings. The channel through which an operator
    -- learns renewal has stopped, if every local alert has been ignored.
    ContactEmail         TEXT    NOT NULL,

    -- The NAME of the secret holding the account key, never the key.
    AccountKeySecretName TEXT    NOT NULL,

    -- Recorded by URL rather than as a boolean: CAs revise their terms, and a
    -- later version may need accepting again. "Accepted something, once" cannot
    -- answer that.
    TermsAccepted        TEXT    NULL,
    TermsAcceptedUtc     TEXT    NULL,

    IsActive             INTEGER NOT NULL DEFAULT 1,

    CreatedUtc           TEXT    NOT NULL,
    ModifiedUtc          TEXT    NULL
);

-- One active account per directory. Two would make "which account issues this
-- certificate" depend on row order, and the account key is what can later revoke
-- it - so the wrong answer is not recoverable by retrying.
CREATE UNIQUE INDEX UX_AcmeAccounts_ActiveDirectory
    ON AcmeAccounts (Directory) WHERE IsActive = 1;


-- -----------------------------------------------------------------------------
-- AcmeOrders: one issuance attempt, from request to outcome.
--
-- Persisted rather than held in memory for the life of a request, for three
-- reasons that each cost something real:
--
--   1. Rate limiting needs history. The limit that actually bites is five failed
--      validations per hostname per hour; a counter that reset on restart would
--      let a crash-loop burn an operator's quota with no record of why.
--   2. Manual DNS-01 can take an operator an hour to publish a TXT record. The
--      order must survive that, and a service restart during it.
--   3. "Issuance failed" a week ago is unanswerable without the identifiers, the
--      challenge type and the CA's own error text.
-- -----------------------------------------------------------------------------
CREATE TABLE AcmeOrders (
    Id                  TEXT    NOT NULL PRIMARY KEY,
    AccountId           TEXT    NOT NULL,

    -- Newline-separated hostnames, denormalised for the same reason as
    -- Certificates.SubjectAltNames: read only as a complete set, never queried
    -- individually, immutable for the order's life.
    Identifiers         TEXT    NOT NULL,

    -- Sorted identifier set, for the CA's duplicate-certificate limit. Sorted
    -- because that limit is on the SET: a server that treated a different
    -- ordering as a different certificate would submit five "different" orders
    -- and hit the limit anyway, having learned nothing.
    IdentifierSetKey    TEXT    NOT NULL,

    -- Registered domain (approximately - see AcmeRateLimiter), for the
    -- per-registered-domain weekly limit.
    RegisteredDomain    TEXT    NOT NULL,

    -- AcmeChallengeType: 0 Http01, 1 Dns01.
    ChallengeType       INTEGER NOT NULL,

    -- AcmeOrderStatus: 0 Created, 1 Pending, 2 Validating, 3 Ready,
    -- 4 Processing, 5 Valid, 6 Invalid, 7 Abandoned.
    Status              INTEGER NOT NULL,

    -- The order's URL at the CA. NULL means the CA never saw this order, which
    -- is exactly what distinguishes a local refusal from a consumed quota slot.
    OrderUrl            TEXT    NULL,

    IssuedCertificateId TEXT    NULL,

    -- The CA's problem-document detail, or a local refusal, in terms an operator
    -- can act on. Never an exception dump: that buries the one useful sentence
    -- and risks carrying request content into a column that gets rendered.
    LastError           TEXT    NULL,

    AttemptCount        INTEGER NOT NULL DEFAULT 0,
    LastAttemptUtc      TEXT    NULL,
    CompletedUtc        TEXT    NULL,

    CreatedUtc          TEXT    NOT NULL,
    ModifiedUtc         TEXT    NULL,

    CONSTRAINT FK_AcmeOrders_Account
        FOREIGN KEY (AccountId) REFERENCES AcmeAccounts (Id) ON DELETE RESTRICT,

    -- SET NULL rather than CASCADE: deleting a certificate must not erase the
    -- record that it was once issued, because that record is rate-limit history.
    CONSTRAINT FK_AcmeOrders_Certificate
        FOREIGN KEY (IssuedCertificateId) REFERENCES Certificates (Id) ON DELETE SET NULL
);

-- The rate limiter's queries, which run before every order. All three are
-- windowed on time, so the time column leads each index.
CREATE INDEX IX_AcmeOrders_SetKey_Attempt
    ON AcmeOrders (IdentifierSetKey, LastAttemptUtc);

CREATE INDEX IX_AcmeOrders_RegisteredDomain_Attempt
    ON AcmeOrders (RegisteredDomain, LastAttemptUtc);

CREATE INDEX IX_AcmeOrders_Status_Attempt
    ON AcmeOrders (Status, LastAttemptUtc);
