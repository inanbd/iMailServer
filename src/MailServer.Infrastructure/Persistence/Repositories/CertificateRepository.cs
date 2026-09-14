using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Persistence.Repositories;

/// <summary>Flat shape of a <c>Certificates</c> row.</summary>
internal sealed class CertificateRow
{
    public Guid Id { get; set; }

    public string Thumbprint { get; set; } = string.Empty;

    public string Subject { get; set; } = string.Empty;

    public string Issuer { get; set; } = string.Empty;

    public string SerialNumber { get; set; } = string.Empty;

    public string SubjectAltNames { get; set; } = string.Empty;

    public int Source { get; set; }

    public int KeyStorage { get; set; }

    public string? KeyFilePath { get; set; }

    public string? KeyPassphraseSecret { get; set; }

    public DateTimeOffset NotBeforeUtc { get; set; }

    public DateTimeOffset NotAfterUtc { get; set; }

    public bool AutoRenew { get; set; }

    public bool IsRenewing { get; set; }

    public DateTimeOffset? LastRenewalUtc { get; set; }

    public string? LastRenewalError { get; set; }

    public DateTimeOffset CreatedUtc { get; set; }

    public DateTimeOffset? ModifiedUtc { get; set; }
}

/// <summary>Flat shape of a <c>CertificateBindings</c> row.</summary>
internal sealed class CertificateBindingRow
{
    public Guid Id { get; set; }

    public string Hostname { get; set; } = string.Empty;

    public Guid CertificateId { get; set; }

    public int Purpose { get; set; }

    public bool IsDefault { get; set; }

    public DateTimeOffset CreatedUtc { get; set; }

    public DateTimeOffset? ModifiedUtc { get; set; }
}

/// <summary>Persists certificate metadata and hostname bindings.</summary>
internal sealed class CertificateRepository(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), ICertificateRepository
{
    /// <summary>
    /// Separates subjectAltName entries in the denormalised column.
    /// </summary>
    /// <remarks>
    /// A newline, not a comma: a dNSName cannot contain either, but a newline makes a row
    /// legible when an operator inspects the table by hand, and comma-separated lists invite
    /// someone to split on ", " with a space and silently produce entries with leading blanks.
    /// </remarks>
    private const char SanSeparator = '\n';

    private const string SelectCertificateColumns = """
        SELECT  Id, Thumbprint, Subject, Issuer, SerialNumber, SubjectAltNames, Source,
                KeyStorage, KeyFilePath, KeyPassphraseSecret, NotBeforeUtc, NotAfterUtc,
                AutoRenew, IsRenewing, LastRenewalUtc, LastRenewalError, CreatedUtc, ModifiedUtc
        FROM    Certificates
        """;

    private const string SelectBindingColumns = """
        SELECT  Id, Hostname, CertificateId, Purpose, IsDefault, CreatedUtc, ModifiedUtc
        FROM    CertificateBindings
        """;

    // ---- Certificates -------------------------------------------------------------------

    public Task<Certificate?> GetAsync(CertificateId id, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            CertificateRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<CertificateRow>(Command(
                    session,
                    SelectCertificateColumns + " WHERE Id = @Id",
                    new { Id = id.Value },
                    ct))
                .ConfigureAwait(false);

            return row is null ? null : Map(row);
        }, cancellationToken);

    public Task<Certificate?> GetByThumbprintAsync(
        CertificateThumbprint thumbprint,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            CertificateRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<CertificateRow>(Command(
                    session,
                    SelectCertificateColumns + " WHERE Thumbprint = @Thumbprint",
                    new { Thumbprint = thumbprint.Value },
                    ct))
                .ConfigureAwait(false);

            return row is null ? null : Map(row);
        }, cancellationToken);

    public Task<IReadOnlyList<Certificate>> GetAllAsync(CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            // Soonest expiry first: it is the order every caller wants, because the
            // certificate closest to expiring is the one that needs attention.
            IEnumerable<CertificateRow> rows = await session.Connection
                .QueryAsync<CertificateRow>(Command(
                    session,
                    SelectCertificateColumns + " ORDER BY NotAfterUtc ASC",
                    null,
                    ct))
                .ConfigureAwait(false);

            return (IReadOnlyList<Certificate>)rows.Select(Map).ToList();
        }, cancellationToken);

    public Task AddAsync(Certificate certificate, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO Certificates
                    (Id, Thumbprint, Subject, Issuer, SerialNumber, SubjectAltNames, Source,
                     KeyStorage, KeyFilePath, KeyPassphraseSecret, NotBeforeUtc, NotAfterUtc,
                     AutoRenew, IsRenewing, LastRenewalUtc, LastRenewalError, CreatedUtc,
                     ModifiedUtc)
                VALUES
                    (@Id, @Thumbprint, @Subject, @Issuer, @SerialNumber, @SubjectAltNames,
                     @Source, @KeyStorage, @KeyFilePath, @KeyPassphraseSecret, @NotBeforeUtc,
                     @NotAfterUtc, @AutoRenew, @IsRenewing, @LastRenewalUtc, @LastRenewalError,
                     @CreatedUtc, @ModifiedUtc)
                """,
                ToRow(certificate),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task UpdateAsync(Certificate certificate, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        return ExecuteAsync(async (session, ct) =>
        {
            // Thumbprint, subject, issuer, SANs and the validity window are deliberately not
            // updatable: they are properties of the certificate itself, and a renewal produces
            // a new row rather than mutating this one. Changing them here would make the audit
            // trail unable to say which certificate was serving at a given time.
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                UPDATE  Certificates
                SET     KeyStorage = @KeyStorage,
                        KeyFilePath = @KeyFilePath,
                        KeyPassphraseSecret = @KeyPassphraseSecret,
                        AutoRenew = @AutoRenew,
                        IsRenewing = @IsRenewing,
                        LastRenewalUtc = @LastRenewalUtc,
                        LastRenewalError = @LastRenewalError,
                        ModifiedUtc = @ModifiedUtc
                WHERE   Id = @Id
                """,
                ToRow(certificate),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task RemoveAsync(CertificateId id, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            // The foreign key is ON DELETE RESTRICT / NO ACTION, so this fails while a binding
            // still points here. That is the intent: the operator rebinds first, rather than
            // discovering at the next handshake that a hostname has no certificate.
            await session.Connection.ExecuteAsync(Command(
                session,
                "DELETE FROM Certificates WHERE Id = @Id",
                new { Id = id.Value },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);

    // ---- Bindings -----------------------------------------------------------------------

    public Task<IReadOnlyList<CertificateBinding>> GetBindingsAsync(
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            IEnumerable<CertificateBindingRow> rows = await session.Connection
                .QueryAsync<CertificateBindingRow>(Command(
                    session,
                    SelectBindingColumns + " ORDER BY Hostname ASC",
                    null,
                    ct))
                .ConfigureAwait(false);

            return (IReadOnlyList<CertificateBinding>)rows.Select(MapBinding).ToList();
        }, cancellationToken);

    public Task<IReadOnlyList<CertificateBinding>> GetBindingsForCertificateAsync(
        CertificateId certificateId,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            IEnumerable<CertificateBindingRow> rows = await session.Connection
                .QueryAsync<CertificateBindingRow>(Command(
                    session,
                    SelectBindingColumns + " WHERE CertificateId = @CertificateId",
                    new { CertificateId = certificateId.Value },
                    ct))
                .ConfigureAwait(false);

            return (IReadOnlyList<CertificateBinding>)rows.Select(MapBinding).ToList();
        }, cancellationToken);

    public Task<CertificateBinding?> GetBindingAsync(
        CertificateBindingId id,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            CertificateBindingRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<CertificateBindingRow>(Command(
                    session,
                    SelectBindingColumns + " WHERE Id = @Id",
                    new { Id = id.Value },
                    ct))
                .ConfigureAwait(false);

            return row is null ? null : MapBinding(row);
        }, cancellationToken);

    public Task<CertificateBinding?> GetBindingByHostnameAsync(
        DomainName hostname,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(hostname);

        return ExecuteAsync(async (session, ct) =>
        {
            CertificateBindingRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<CertificateBindingRow>(Command(
                    session,
                    SelectBindingColumns + " WHERE Hostname = @Hostname",
                    new { Hostname = hostname.Value },
                    ct))
                .ConfigureAwait(false);

            return row is null ? null : MapBinding(row);
        }, cancellationToken);
    }

    public Task AddBindingAsync(CertificateBinding binding, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(binding);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO CertificateBindings
                    (Id, Hostname, CertificateId, Purpose, IsDefault, CreatedUtc, ModifiedUtc)
                VALUES
                    (@Id, @Hostname, @CertificateId, @Purpose, @IsDefault, @CreatedUtc,
                     @ModifiedUtc)
                """,
                ToBindingRow(binding),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task UpdateBindingAsync(
        CertificateBinding binding,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(binding);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                UPDATE  CertificateBindings
                SET     CertificateId = @CertificateId,
                        Purpose = @Purpose,
                        IsDefault = @IsDefault,
                        ModifiedUtc = @ModifiedUtc
                WHERE   Id = @Id
                """,
                ToBindingRow(binding),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task RemoveBindingAsync(
        CertificateBindingId id,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                "DELETE FROM CertificateBindings WHERE Id = @Id",
                new { Id = id.Value },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);

    public Task ClearOtherDefaultsAsync(
        CertificateBindingId keep,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            // One statement, because the unique filtered index permits at most one default
            // row. Clearing the others one at a time would transiently violate it and fail
            // halfway through, leaving the configuration in a state neither the operator nor
            // the code intended.
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                UPDATE  CertificateBindings
                SET     IsDefault = 0
                WHERE   Id <> @Keep AND IsDefault = 1
                """,
                new { Keep = keep.Value },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);

    // ---- Mapping ------------------------------------------------------------------------

    private static Certificate Map(CertificateRow row) =>
        new(
            new CertificateId(row.Id),
            CertificateThumbprint.Parse(row.Thumbprint),
            row.Subject,
            row.Issuer,
            row.SerialNumber,
            ParseSubjectAltNames(row.SubjectAltNames),
            (CertificateSource)row.Source,
            CertificateKeyLocation.Rehydrate(
                (CertificateKeyStorage)row.KeyStorage,
                CertificateThumbprint.Parse(row.Thumbprint),
                row.KeyFilePath,
                row.KeyPassphraseSecret),
            row.NotBeforeUtc,
            row.NotAfterUtc,
            row.AutoRenew,
            row.IsRenewing,
            row.LastRenewalUtc,
            row.LastRenewalError,
            row.CreatedUtc,
            row.ModifiedUtc);

    /// <remarks>
    /// Unparseable entries are skipped rather than throwing. A row written by an older version
    /// whose SAN rules differed must still load: an unloadable certificate row is an outage,
    /// whereas one that reports slightly narrower coverage is a dashboard entry.
    /// </remarks>
    private static List<CertificateSubjectName> ParseSubjectAltNames(string packed)
    {
        List<CertificateSubjectName> names = [];

        foreach (string entry in packed.Split(
                     SanSeparator,
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (CertificateSubjectName.TryParse(entry, out CertificateSubjectName? parsed))
            {
                names.Add(parsed);
            }
        }

        return names;
    }

    private static CertificateRow ToRow(Certificate certificate) => new()
    {
        Id = certificate.Id.Value,
        Thumbprint = certificate.Thumbprint.Value,
        Subject = certificate.Subject,
        Issuer = certificate.Issuer,
        SerialNumber = certificate.SerialNumber,
        SubjectAltNames = string.Join(
            SanSeparator,
            certificate.SubjectAlternativeNames.Select(static n => n.Value)),
        Source = (int)certificate.Source,
        KeyStorage = (int)certificate.KeyLocation.Storage,
        KeyFilePath = certificate.KeyLocation.RelativeFilePath,
        KeyPassphraseSecret = certificate.KeyLocation.PassphraseSecretName,
        NotBeforeUtc = certificate.NotBeforeUtc,
        NotAfterUtc = certificate.NotAfterUtc,
        AutoRenew = certificate.AutoRenew,
        IsRenewing = certificate.IsRenewing,
        LastRenewalUtc = certificate.LastRenewalUtc,
        LastRenewalError = certificate.LastRenewalError,
        CreatedUtc = certificate.CreatedUtc,
        ModifiedUtc = certificate.ModifiedUtc,
    };

    private static CertificateBinding MapBinding(CertificateBindingRow row) =>
        new(
            new CertificateBindingId(row.Id),
            DomainName.Parse(row.Hostname),
            new CertificateId(row.CertificateId),
            (CertificatePurpose)row.Purpose,
            row.IsDefault,
            row.CreatedUtc,
            row.ModifiedUtc);

    private static CertificateBindingRow ToBindingRow(CertificateBinding binding) => new()
    {
        Id = binding.Id.Value,
        Hostname = binding.Hostname.Value,
        CertificateId = binding.CertificateId.Value,
        Purpose = (int)binding.Purpose,
        IsDefault = binding.IsDefault,
        CreatedUtc = binding.CreatedUtc,
        ModifiedUtc = binding.ModifiedUtc,
    };
}
