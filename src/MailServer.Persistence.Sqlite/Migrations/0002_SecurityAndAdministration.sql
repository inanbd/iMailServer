-- =============================================================================
-- AetherMail Server - security and administration (SQLite)
-- Milestone 2
--
-- Adds the administrator identity, the security event log, and protected secret
-- storage. Purely additive: no existing table is altered, so this migration is not
-- marked @Destructive and needs no pre-upgrade backup.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- AdminAccounts: the identity that guards the administration console.
--
-- Milestone 2 has exactly one row, the built-in 'Administrator'. The table is
-- nonetheless keyed and indexed as though there will be several, because delegated
-- administration is a permission set rather than a rewrite.
-- -----------------------------------------------------------------------------
CREATE TABLE AdminAccounts (
    Id                  TEXT    NOT NULL PRIMARY KEY,
    Name                TEXT    NOT NULL,

    -- Argon2id verifier in PHC string format:
    --   $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
    -- The work factors travel WITH the hash rather than living in configuration, so
    -- raising them later does not invalidate existing passwords. An old hash still
    -- verifies against its own parameters and is upgraded on the next successful
    -- sign-in, which is the only moment the plaintext is available.
    PasswordHash        TEXT    NOT NULL,

    -- Same format. Hashed rather than encrypted because the recovery key grants full
    -- control of the server: a database dump must not yield it. NULL once consumed,
    -- until a replacement is issued in the same transaction.
    RecoveryKeyHash     TEXT    NULL,

    -- AdminPermission flags.
    Permissions         INTEGER NOT NULL DEFAULT 0,

    -- Lockout state is PERSISTED, not held in memory. A counter that reset when the
    -- service restarted would be no lockout at all.
    ConsecutiveFailures INTEGER NOT NULL DEFAULT 0,
    LastFailureUtc      TEXT    NULL,
    LockedOutUntilUtc   TEXT    NULL,

    LastSignInUtc       TEXT    NULL,

    -- Set after a recovery-key reset. The authorization behavior refuses everything
    -- except changing the password and signing out while this is set, so a recovery
    -- key is a route back in rather than a standing bypass of the password.
    MustChangePassword  INTEGER NOT NULL DEFAULT 0,

    CreatedUtc          TEXT    NOT NULL,
    PasswordChangedUtc  TEXT    NULL,

    CONSTRAINT CK_AdminAccounts_Failures
        CHECK (ConsecutiveFailures >= 0)
);

-- UNIQUE: it is what decides the winner when two clients race to complete first-run
-- setup. The handler's pre-check only produces a better message in the common case.
CREATE UNIQUE INDEX UX_AdminAccounts_Name ON AdminAccounts (Name);


-- -----------------------------------------------------------------------------
-- SecurityEvents: what happened to the security posture.
--
-- Deliberately separate from AuditRecords. The audit trail answers "who changed what"
-- and is written INSIDE the transaction that made the change. This answers "what
-- happened to the security posture" and is written OUT OF BAND, because the events
-- worth recording mostly occur where no transaction exists, and those that occur
-- inside a failing one must survive its rollback: an attacker who can make an
-- operation fail must not thereby erase the record of their attempt.
--
-- The volumes differ by orders of magnitude too. A brute-force run produces thousands
-- of security events and zero audit records; mixing them would make the audit trail
-- unreadable precisely when it matters most.
--
-- NEVER contains a credential: not an attempted password, not a presented session
-- token, not a recovery key.
-- -----------------------------------------------------------------------------
CREATE TABLE SecurityEvents (
    Id            TEXT    NOT NULL PRIMARY KEY,
    TimestampUtc  TEXT    NOT NULL,

    -- SecurityEventType.
    EventType     INTEGER NOT NULL,

    -- Who it concerns. NULL for a failure against an account that does not exist;
    -- the attempted name is deliberately not stored, because it is attacker-controlled
    -- text that would then be rendered in an admin UI.
    Subject       TEXT    NULL,

    -- Where it came from: a client description or a session id.
    Origin        TEXT    NULL,

    Description   TEXT    NOT NULL,
    MachineName   TEXT    NOT NULL,
    CorrelationId TEXT    NOT NULL,

    -- Denormalised from the event type so the "show me only what matters" filter is an
    -- index seek rather than a large IN list that has to change whenever the enum does.
    IsAlarming    INTEGER NOT NULL DEFAULT 0
);

-- The viewer is almost always "most recent first".
CREATE INDEX IX_SecurityEvents_TimestampUtc ON SecurityEvents (TimestampUtc DESC);

-- Serves the failed-sign-in counter on the security overview, and type filtering.
CREATE INDEX IX_SecurityEvents_EventType ON SecurityEvents (EventType, TimestampUtc DESC);

-- "Show me only what matters", the default view during an incident.
CREATE INDEX IX_SecurityEvents_Alarming ON SecurityEvents (IsAlarming, TimestampUtc DESC);

-- Joins a security event to the audit records and log lines for the same operation.
CREATE INDEX IX_SecurityEvents_CorrelationId ON SecurityEvents (CorrelationId);


-- -----------------------------------------------------------------------------
-- ProtectedSecrets: values the server must be able to read back.
--
-- Holds SQL Server connection strings, smarthost credentials, certificate passphrases
-- and, from later milestones, the ACME account key and HMAC signing keys.
--
-- ProtectedValue is ALREADY ENCRYPTED before it reaches SQL, by ISecretProtector
-- (DPAPI with additional entropy in production). A database backup, a replica or a
-- support engineer with read access sees only ciphertext.
--
-- DPAPI is machine-scoped, so this table is NOT portable between machines. Restoring
-- onto different hardware requires the backup passphrase; see docs/BackupRestore.md.
--
-- Passwords never appear here. Anything that goes through this table is something the
-- server must decrypt; a password is not, and is hashed in AdminAccounts instead.
-- -----------------------------------------------------------------------------
CREATE TABLE ProtectedSecrets (
    SecretName       TEXT NOT NULL PRIMARY KEY,
    ProtectedValue   TEXT NOT NULL,
    Description      TEXT NULL,

    -- Which protector encrypted it, so a scheme change can be detected and the value
    -- re-wrapped rather than failing to decrypt with a confusing error.
    ProtectionScheme TEXT NOT NULL,

    CreatedUtc       TEXT NOT NULL,
    ModifiedUtc      TEXT NULL
);
