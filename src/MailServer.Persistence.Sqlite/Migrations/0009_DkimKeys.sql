-- =============================================================================
-- AetherMail Server - DKIM signing keys (SQLite)
-- Milestone 9
--
-- Purely additive: two new tables and their indexes. No existing table is
-- altered, so this carries no destructive directive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- DkimKeys: what the server knows ABOUT a DKIM signing key, never the key
-- itself.
--
-- Mirrors the split Certificates already makes: this row is metadata plus a
-- pointer (the row's own Id) to where the private key actually lives, in
-- DkimPrivateKeys below. PublicKeyBase64 is NOT secret - it is the exact
-- value this key's DNS TXT record publishes as its p= tag - so it lives here
-- directly rather than behind the same indirection.
-- -----------------------------------------------------------------------------
CREATE TABLE DkimKeys (
    Id                  TEXT    NOT NULL PRIMARY KEY,
    DomainId            TEXT    NOT NULL,

    -- A DNS label: {Selector}._domainkey.{domain}.
    Selector            TEXT    NOT NULL,

    -- DkimKeyAlgorithm: 0 RsaSha256, 1 Ed25519Sha256 (reserved, unused).
    Algorithm           INTEGER NOT NULL,

    PublicKeyBase64     TEXT    NOT NULL,
    KeyLengthBits       INTEGER NOT NULL,

    -- DkimKeyStatus: 0 Generated, 1 Published, 2 Active, 3 Retired.
    Status              INTEGER NOT NULL DEFAULT 0,

    CreatedUtc          TEXT    NOT NULL,
    ModifiedUtc         TEXT    NULL,
    PublishedUtc        TEXT    NULL,
    ActivatedUtc        TEXT    NULL,
    RetiredUtc          TEXT    NULL,

    -- When it becomes safe to remove this key's DNS record and delete its
    -- private key: RetiredUtc plus the rotation grace window. NULL until
    -- retirement - see DkimKey.Retire.
    SafeToDeleteAfterUtc TEXT   NULL,

    CONSTRAINT FK_DkimKeys_Domain
        FOREIGN KEY (DomainId) REFERENCES Domains (Id) ON DELETE CASCADE,

    CONSTRAINT CK_DkimKeys_Status CHECK (Status BETWEEN 0 AND 3)
) STRICT;

-- A selector is scoped to its domain: two different domains may both publish
-- "mail202609", but the same domain must never publish it twice - DNS would
-- have nowhere to put the second record.
CREATE UNIQUE INDEX UX_DkimKeys_Domain_Selector ON DkimKeys (DomainId, Selector);

-- "The active key for this domain" is the signer's hot-path lookup, once per
-- outbound message.
CREATE INDEX IX_DkimKeys_Domain_Status ON DkimKeys (DomainId, Status);

-- A future cleanup job's query: retired keys whose grace window has passed.
CREATE INDEX IX_DkimKeys_SafeToDelete
    ON DkimKeys (SafeToDeleteAfterUtc)
    WHERE Status = 3;


-- -----------------------------------------------------------------------------
-- DkimPrivateKeys: the private half, and nothing else.
--
-- Split into its own table - rather than a nullable column on DkimKeys - so
-- that no query against key metadata (the admin UI's key list, the signer's
-- "find the active key" lookup) can accidentally project a column holding
-- key material; the repository method that maps DkimKeys rows to the DkimKey
-- aggregate never joins this table at all.
-- -----------------------------------------------------------------------------
CREATE TABLE DkimPrivateKeys (
    DkimKeyId               TEXT NOT NULL PRIMARY KEY,

    -- PKCS#8, encrypted through ISecretProtector (DPAPI with additional
    -- entropy) before it reaches this column. Never logged, never returned
    -- by any listing - see docs/DKIM.md's "Private key storage" section.
    ProtectedPrivateKey      BLOB NOT NULL,

    CreatedUtc               TEXT NOT NULL,

    CONSTRAINT FK_DkimPrivateKeys_DkimKey
        FOREIGN KEY (DkimKeyId) REFERENCES DkimKeys (Id) ON DELETE CASCADE
) STRICT;
