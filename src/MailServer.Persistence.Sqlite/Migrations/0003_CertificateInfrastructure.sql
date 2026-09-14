-- =============================================================================
-- AetherMail Server - certificate infrastructure (SQLite)
-- Milestone 3
--
-- Adds certificate metadata and the hostname bindings that decide which certificate
-- is presented during a TLS handshake. Purely additive: no existing table is altered,
-- so this migration is not marked @Destructive and needs no pre-upgrade backup.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- Certificates: what the server knows ABOUT a certificate, never the certificate.
--
-- No private key, no certificate bytes, no PFX passphrase appears in this table. It
-- holds the metadata the server reasons about - subject, issuer, SAN coverage,
-- validity window - plus a POINTER to where the real thing lives.
--
-- That separation is what makes rule 105's "no private keys in logs" cheap to
-- guarantee: the certificate list the admin UI renders, the audit records written
-- about it, and any log line interpolating a row simply have no key material
-- available to leak.
-- -----------------------------------------------------------------------------
CREATE TABLE Certificates (
    Id                  TEXT    NOT NULL PRIMARY KEY,

    -- The certificate's identity everywhere outside this database. Upper-case hex,
    -- which is the form X509Certificate2.Thumbprint and the Windows store both use.
    Thumbprint          TEXT    NOT NULL,

    Subject             TEXT    NOT NULL,
    Issuer              TEXT    NOT NULL,
    SerialNumber        TEXT    NOT NULL DEFAULT '',

    -- The dNSName entries from subjectAltName, newline-separated.
    --
    -- Denormalised deliberately. A separate table would be the textbook answer, but
    -- SANs are only ever read as a complete set alongside their certificate, are
    -- never queried individually, and are immutable for the certificate's lifetime -
    -- a reissue is a new row. A child table would add a join to every read and buy
    -- nothing. The common name is NOT stored, because RFC 6125 deprecated CN-based
    -- name matching and no current client consults it.
    SubjectAltNames     TEXT    NOT NULL,

    -- CertificateSource: 0 SelfSigned, 1 Acme, 2 ImportedPfx, 3 WindowsStore.
    Source              INTEGER NOT NULL,

    -- CertificateKeyStorage: 0 WindowsCertificateStore, 1 ProtectedPfxFile.
    KeyStorage          INTEGER NOT NULL,

    -- RELATIVE to the configured certificate directory, never absolute. An absolute
    -- path here would be an arbitrary-file-read primitive the moment anything could
    -- write to this column; a relative one is resolved through the containment check
    -- in IServerPaths and cannot escape.
    KeyFilePath         TEXT    NULL,

    -- The NAME of the secret holding the PKCS#12 passphrase, never the passphrase.
    -- The value itself lives in ProtectedSecrets, DPAPI-encrypted.
    KeyPassphraseSecret TEXT    NULL,

    NotBeforeUtc        TEXT    NOT NULL,
    NotAfterUtc         TEXT    NOT NULL,

    -- Only ACME certificates can be true: this server cannot reissue an imported or
    -- store-held certificate, so offering auto-renew for one would be a switch that
    -- silently does nothing while the certificate expires. Enforced in the aggregate
    -- and again here, because a switch that lies is worse than no switch.
    AutoRenew           INTEGER NOT NULL DEFAULT 0,

    IsRenewing          INTEGER NOT NULL DEFAULT 0,
    LastRenewalUtc      TEXT    NULL,

    -- Why the last renewal failed, so the UI can show it beside the certificate
    -- instead of asking an operator to correlate a dashboard warning with a log
    -- search. A description written by the handler - never an exception dump, which
    -- is how key material ends up in a database column.
    LastRenewalError    TEXT    NULL,

    CreatedUtc          TEXT    NOT NULL,
    ModifiedUtc         TEXT    NULL,

    CONSTRAINT CK_Certificates_Validity
        CHECK (NotAfterUtc > NotBeforeUtc),

    -- A file-backed certificate is useless without the passphrase to open it, and a
    -- store-backed one must not carry a path. Enforcing the pairing here means a
    -- half-written row fails at INSERT rather than at the first TLS handshake.
    CONSTRAINT CK_Certificates_KeyLocation
        CHECK (
            (KeyStorage = 0 AND KeyFilePath IS NULL AND KeyPassphraseSecret IS NULL)
         OR (KeyStorage = 1 AND KeyFilePath IS NOT NULL AND KeyPassphraseSecret IS NOT NULL)
        ),

    -- Only source 1 (Acme) may auto-renew.
    CONSTRAINT CK_Certificates_AutoRenew
        CHECK (AutoRenew = 0 OR Source = 1)
);

-- UNIQUE: a thumbprint identifies a certificate exactly. Importing the same file
-- twice must be a clear duplicate error, not two rows that later disagree about
-- which is bound where.
CREATE UNIQUE INDEX UX_Certificates_Thumbprint ON Certificates (Thumbprint);

-- The lifecycle service's only query: "what expires soonest". Ordering by an indexed
-- column keeps a check that runs every 12 hours from scanning the table.
CREATE INDEX IX_Certificates_NotAfterUtc ON Certificates (NotAfterUtc);


-- -----------------------------------------------------------------------------
-- CertificateBindings: hostname + purpose -> certificate.
--
-- This is what a TLS handshake resolves against. A client connects, offers an SNI
-- hostname, and the server must answer "which certificate" in microseconds; an
-- explicit mapping makes that cheap and, more importantly, deterministic when two
-- certificates both cover the same name.
--
-- A binding outlives the certificates it points at. A certificate is replaced every
-- 60-90 days; the statement "mail.example.com is served by whatever currently covers
-- it" does not change. Renewal therefore repoints one row instead of rewriting
-- configuration, which is what makes hot reload a reference swap.
-- -----------------------------------------------------------------------------
CREATE TABLE CertificateBindings (
    Id            TEXT    NOT NULL PRIMARY KEY,

    -- ASCII A-label form, so an internationalised hostname compares byte-for-byte
    -- against the SNI value a client sends.
    Hostname      TEXT    NOT NULL,

    CertificateId TEXT    NOT NULL,

    -- CertificatePurpose flags: 1 SmtpInbound, 2 SmtpSubmission, 4 MailboxAccess,
    -- 8 Https. 15 is All.
    Purpose       INTEGER NOT NULL,

    -- Presented when a client offers no SNI hostname, or one nothing matches. Not
    -- optional in practice: SNI is an extension, older MTAs still connect without it,
    -- and inbound mail from them is exactly the traffic a mail server cannot drop.
    IsDefault     INTEGER NOT NULL DEFAULT 0,

    CreatedUtc    TEXT    NOT NULL,
    ModifiedUtc   TEXT    NULL,

    -- RESTRICT, not CASCADE. Deleting a certificate that is still bound would silently
    -- remove the binding and leave that hostname with no certificate - discovered at
    -- the next handshake. Refusing the delete forces the operator to rebind first.
    CONSTRAINT FK_CertificateBindings_Certificate
        FOREIGN KEY (CertificateId) REFERENCES Certificates (Id) ON DELETE RESTRICT,

    CONSTRAINT CK_CertificateBindings_Purpose
        CHECK (Purpose > 0)
);

-- One binding per hostname. Two would make which certificate gets presented depend on
-- row order, and a TLS configuration that varies between restarts is not diagnosable.
CREATE UNIQUE INDEX UX_CertificateBindings_Hostname ON CertificateBindings (Hostname);

-- At most one default. A partial index expresses "unique among the rows where
-- IsDefault = 1" exactly, so the invariant is held by the database rather than by
-- every code path that sets the flag.
CREATE UNIQUE INDEX UX_CertificateBindings_Default
    ON CertificateBindings (IsDefault) WHERE IsDefault = 1;

CREATE INDEX IX_CertificateBindings_CertificateId
    ON CertificateBindings (CertificateId);
