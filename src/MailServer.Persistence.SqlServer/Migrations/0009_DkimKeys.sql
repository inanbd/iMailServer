-- =============================================================================
-- AetherMail Server - DKIM signing keys (Microsoft SQL Server)
-- Milestone 9
--
-- The SQL Server counterpart of the SQLite 0009 script. The two are kept
-- deliberately in step; anything that cannot be expressed identically is
-- called out in a comment rather than allowed to diverge silently.
--
-- Purely additive: no existing table is altered, so this is not marked
-- @Destructive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- DkimKeys: what the server knows ABOUT a DKIM signing key, never the key
-- itself. Mirrors the split Certificates already makes: metadata plus a
-- pointer (this row's own Id) to where the private key lives, in
-- DkimPrivateKeys below.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.DkimKeys (
    Id                   UNIQUEIDENTIFIER  NOT NULL,
    DomainId             UNIQUEIDENTIFIER  NOT NULL,

    -- A DNS label: {Selector}._domainkey.{domain}.
    Selector             VARCHAR(63)       NOT NULL,

    -- DkimKeyAlgorithm: 0 RsaSha256, 1 Ed25519Sha256 (reserved, unused).
    Algorithm            INT               NOT NULL,

    -- Not secret: the exact p= tag value this key's DNS TXT record publishes.
    PublicKeyBase64      NVARCHAR(MAX)     NOT NULL,
    KeyLengthBits         INT              NOT NULL,

    -- DkimKeyStatus: 0 Generated, 1 Published, 2 Active, 3 Retired.
    Status               INT               NOT NULL
        CONSTRAINT DF_DkimKeys_Status DEFAULT (0),

    CreatedUtc           DATETIMEOFFSET(7) NOT NULL,
    ModifiedUtc          DATETIMEOFFSET(7) NULL,
    PublishedUtc         DATETIMEOFFSET(7) NULL,
    ActivatedUtc         DATETIMEOFFSET(7) NULL,
    RetiredUtc           DATETIMEOFFSET(7) NULL,

    -- When it becomes safe to remove this key's DNS record and delete its
    -- private key: RetiredUtc plus the rotation grace window.
    SafeToDeleteAfterUtc DATETIMEOFFSET(7) NULL,

    CONSTRAINT PK_DkimKeys PRIMARY KEY NONCLUSTERED (Id),

    CONSTRAINT FK_DkimKeys_Domain
        FOREIGN KEY (DomainId) REFERENCES dbo.Domains (Id) ON DELETE CASCADE,

    CONSTRAINT CK_DkimKeys_Status CHECK (Status BETWEEN 0 AND 3)
);

-- A selector is scoped to its domain: two different domains may both publish
-- "mail202609", but the same domain must never publish it twice.
CREATE UNIQUE CLUSTERED INDEX UX_DkimKeys_Domain_Selector
    ON dbo.DkimKeys (DomainId, Selector);

-- "The active key for this domain" is the signer's hot-path lookup, once per
-- outbound message.
CREATE INDEX IX_DkimKeys_Domain_Status ON dbo.DkimKeys (DomainId, Status);

-- A future cleanup job's query: retired keys whose grace window has passed.
CREATE INDEX IX_DkimKeys_SafeToDelete
    ON dbo.DkimKeys (SafeToDeleteAfterUtc)
    WHERE Status = 3;


-- -----------------------------------------------------------------------------
-- DkimPrivateKeys: the private half, and nothing else. Split into its own
-- table so that no query against key metadata can accidentally project a
-- column holding key material.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.DkimPrivateKeys (
    DkimKeyId            UNIQUEIDENTIFIER NOT NULL,

    -- PKCS#8, encrypted through ISecretProtector before it reaches this
    -- column. Never logged, never returned by any listing.
    ProtectedPrivateKey  VARBINARY(MAX)   NOT NULL,

    CreatedUtc           DATETIMEOFFSET(7) NOT NULL,

    CONSTRAINT PK_DkimPrivateKeys PRIMARY KEY NONCLUSTERED (DkimKeyId),

    CONSTRAINT FK_DkimPrivateKeys_DkimKey
        FOREIGN KEY (DkimKeyId) REFERENCES dbo.DkimKeys (Id) ON DELETE CASCADE
);
