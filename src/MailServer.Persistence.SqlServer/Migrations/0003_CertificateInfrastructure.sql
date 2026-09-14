-- =============================================================================
-- AetherMail Server - certificate infrastructure (Microsoft SQL Server)
-- Milestone 3
--
-- The SQL Server counterpart of the SQLite 0003 script. The two are kept deliberately
-- in step; anything that cannot be expressed identically is called out in a comment
-- rather than allowed to diverge silently.
--
-- Purely additive: no existing table is altered, so this is not marked @Destructive.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- Certificates: what the server knows ABOUT a certificate, never the certificate.
--
-- No private key, no certificate bytes, no PFX passphrase appears in this table. It
-- holds metadata plus a POINTER to where the real thing lives, which is what makes
-- rule 105's "no private keys in logs" cheap to guarantee everywhere downstream.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.Certificates (
    Id                  UNIQUEIDENTIFIER  NOT NULL,

    -- Upper-case hexadecimal, matching X509Certificate2.Thumbprint and the Windows
    -- certificate store. VARCHAR rather than NVARCHAR: hexadecimal is ASCII, and the
    -- narrower type halves the index.
    Thumbprint          VARCHAR(64)       NOT NULL,

    Subject             NVARCHAR(1024)    NOT NULL,
    Issuer              NVARCHAR(1024)    NOT NULL,
    SerialNumber        VARCHAR(128)      NOT NULL
        CONSTRAINT DF_Certificates_Serial DEFAULT (''),

    -- The dNSName entries from subjectAltName, newline-separated. Denormalised: SANs
    -- are read only as a complete set with their certificate, are never queried
    -- individually, and are immutable for its lifetime. A child table would add a
    -- join to every read and buy nothing. The common name is deliberately absent -
    -- RFC 6125 deprecated CN-based matching and no current client consults it.
    SubjectAltNames     NVARCHAR(MAX)     NOT NULL,

    -- CertificateSource: 0 SelfSigned, 1 Acme, 2 ImportedPfx, 3 WindowsStore.
    Source              INT               NOT NULL,

    -- CertificateKeyStorage: 0 WindowsCertificateStore, 1 ProtectedPfxFile.
    KeyStorage          INT               NOT NULL,

    -- RELATIVE to the configured certificate directory, never absolute.
    KeyFilePath         NVARCHAR(512)     NULL,

    -- The NAME of the secret holding the PKCS#12 passphrase, never the passphrase.
    KeyPassphraseSecret NVARCHAR(256)     NULL,

    NotBeforeUtc        DATETIMEOFFSET(7) NOT NULL,
    NotAfterUtc         DATETIMEOFFSET(7) NOT NULL,

    AutoRenew           BIT               NOT NULL
        CONSTRAINT DF_Certificates_AutoRenew DEFAULT (0),
    IsRenewing          BIT               NOT NULL
        CONSTRAINT DF_Certificates_IsRenewing DEFAULT (0),
    LastRenewalUtc      DATETIMEOFFSET(7) NULL,
    LastRenewalError    NVARCHAR(2048)    NULL,

    CreatedUtc          DATETIMEOFFSET(7) NOT NULL,
    ModifiedUtc         DATETIMEOFFSET(7) NULL,

    -- NONCLUSTERED on a v7 GUID for the same reason as every other table here: the
    -- clustered index goes on the time-ordered access path, not the key.
    CONSTRAINT PK_Certificates PRIMARY KEY NONCLUSTERED (Id),

    CONSTRAINT CK_Certificates_Validity
        CHECK (NotAfterUtc > NotBeforeUtc),

    -- A file-backed certificate is useless without the passphrase to open it, and a
    -- store-backed one must not carry a path. A half-written row fails at INSERT
    -- rather than at the first TLS handshake.
    CONSTRAINT CK_Certificates_KeyLocation
        CHECK (
            (KeyStorage = 0 AND KeyFilePath IS NULL AND KeyPassphraseSecret IS NULL)
         OR (KeyStorage = 1 AND KeyFilePath IS NOT NULL AND KeyPassphraseSecret IS NOT NULL)
        ),

    -- Only source 1 (Acme) may auto-renew: this server cannot reissue an imported or
    -- store-held certificate, so the switch would silently do nothing.
    CONSTRAINT CK_Certificates_AutoRenew
        CHECK (AutoRenew = 0 OR Source = 1)
);

CREATE UNIQUE INDEX UX_Certificates_Thumbprint ON dbo.Certificates (Thumbprint);

-- The lifecycle service's only query: "what expires soonest".
CREATE CLUSTERED INDEX IX_Certificates_NotAfterUtc ON dbo.Certificates (NotAfterUtc);


-- -----------------------------------------------------------------------------
-- CertificateBindings: hostname + purpose -> certificate.
--
-- What a TLS handshake resolves against. A binding outlives the certificates it
-- points at, so renewal repoints one row rather than rewriting configuration - which
-- is what makes hot reload a reference swap instead of a listener restart.
-- -----------------------------------------------------------------------------
CREATE TABLE dbo.CertificateBindings (
    Id            UNIQUEIDENTIFIER  NOT NULL,

    -- ASCII A-label form, so an internationalised hostname compares byte-for-byte
    -- against the SNI value a client sends.
    Hostname      VARCHAR(255)      NOT NULL,

    CertificateId UNIQUEIDENTIFIER  NOT NULL,

    -- CertificatePurpose flags: 1 SmtpInbound, 2 SmtpSubmission, 4 MailboxAccess,
    -- 8 Https. 15 is All.
    Purpose       INT               NOT NULL,

    IsDefault     BIT               NOT NULL
        CONSTRAINT DF_CertificateBindings_IsDefault DEFAULT (0),

    CreatedUtc    DATETIMEOFFSET(7) NOT NULL,
    ModifiedUtc   DATETIMEOFFSET(7) NULL,

    CONSTRAINT PK_CertificateBindings PRIMARY KEY NONCLUSTERED (Id),

    -- NO ACTION is SQL Server's RESTRICT: deleting a certificate that is still bound
    -- would leave that hostname with no certificate, discovered at the next handshake.
    -- Refusing the delete forces the operator to rebind first.
    CONSTRAINT FK_CertificateBindings_Certificate
        FOREIGN KEY (CertificateId) REFERENCES dbo.Certificates (Id) ON DELETE NO ACTION,

    CONSTRAINT CK_CertificateBindings_Purpose
        CHECK (Purpose > 0)
);

-- One binding per hostname: two would make the certificate presented depend on row
-- order, and a TLS configuration that varies between restarts is not diagnosable.
CREATE UNIQUE CLUSTERED INDEX UX_CertificateBindings_Hostname
    ON dbo.CertificateBindings (Hostname);

-- At most one default. A filtered unique index expresses "unique among the rows where
-- IsDefault = 1" exactly, so the database holds the invariant rather than every code
-- path that sets the flag. This is the SQL Server spelling of SQLite's partial index.
CREATE UNIQUE INDEX UX_CertificateBindings_Default
    ON dbo.CertificateBindings (IsDefault)
    WHERE IsDefault = 1;

CREATE INDEX IX_CertificateBindings_CertificateId
    ON dbo.CertificateBindings (CertificateId);
