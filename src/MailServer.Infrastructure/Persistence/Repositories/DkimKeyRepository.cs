using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Persistence.Repositories;

/// <summary>Flat shape of a <c>DkimKeys</c> row.</summary>
internal sealed class DkimKeyRow
{
    public Guid Id { get; set; }

    public Guid DomainId { get; set; }

    public string Selector { get; set; } = string.Empty;

    public int Algorithm { get; set; }

    public string PublicKeyBase64 { get; set; } = string.Empty;

    public int KeyLengthBits { get; set; }

    public int Status { get; set; }

    public DateTimeOffset CreatedUtc { get; set; }

    public DateTimeOffset? ModifiedUtc { get; set; }

    public DateTimeOffset? PublishedUtc { get; set; }

    public DateTimeOffset? ActivatedUtc { get; set; }

    public DateTimeOffset? RetiredUtc { get; set; }

    public DateTimeOffset? SafeToDeleteAfterUtc { get; set; }
}

/// <summary>Persists DKIM key metadata and, in a companion table, the protected private key.</summary>
internal sealed class DkimKeyRepository(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect,
    ISecretProtector protector,
    IClock clock)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), IDkimKeyRepository
{
    private const string SelectColumns = """
        SELECT  Id, DomainId, Selector, Algorithm, PublicKeyBase64, KeyLengthBits, Status,
                CreatedUtc, ModifiedUtc, PublishedUtc, ActivatedUtc, RetiredUtc,
                SafeToDeleteAfterUtc
        FROM    DkimKeys
        """;

    public Task<DkimKey?> GetAsync(DkimKeyId id, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            DkimKeyRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<DkimKeyRow>(Command(
                    session,
                    SelectColumns + " WHERE Id = @Id",
                    new { Id = id.Value },
                    ct))
                .ConfigureAwait(false);

            return row is null ? null : Map(row);
        }, cancellationToken);

    public Task<IReadOnlyList<DkimKey>> GetForDomainAsync(
        DomainId domainId,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            IEnumerable<DkimKeyRow> rows = await session.Connection
                .QueryAsync<DkimKeyRow>(Command(
                    session,
                    SelectColumns + " WHERE DomainId = @DomainId ORDER BY CreatedUtc ASC",
                    new { DomainId = domainId.Value },
                    ct))
                .ConfigureAwait(false);

            return (IReadOnlyList<DkimKey>)rows.Select(Map).ToList();
        }, cancellationToken);

    public Task<DkimKey?> GetActiveForDomainAsync(
        DomainId domainId,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            DkimKeyRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<DkimKeyRow>(Command(
                    session,
                    SelectColumns + " WHERE DomainId = @DomainId AND Status = @Active",
                    new { DomainId = domainId.Value, Active = (int)DkimKeyStatus.Active },
                    ct))
                .ConfigureAwait(false);

            return row is null ? null : Map(row);
        }, cancellationToken);

    public Task<IReadOnlyList<DkimKey>> GetAllAsync(CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            IEnumerable<DkimKeyRow> rows = await session.Connection
                .QueryAsync<DkimKeyRow>(Command(
                    session,
                    SelectColumns + " ORDER BY CreatedUtc ASC",
                    null,
                    ct))
                .ConfigureAwait(false);

            return (IReadOnlyList<DkimKey>)rows.Select(Map).ToList();
        }, cancellationToken);

    public Task AddAsync(DkimKey key, byte[] pkcs8PrivateKey, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(pkcs8PrivateKey);

        byte[] protectedPrivateKey = protector.Protect(pkcs8PrivateKey);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO DkimKeys
                    (Id, DomainId, Selector, Algorithm, PublicKeyBase64, KeyLengthBits, Status,
                     CreatedUtc, ModifiedUtc, PublishedUtc, ActivatedUtc, RetiredUtc,
                     SafeToDeleteAfterUtc)
                VALUES
                    (@Id, @DomainId, @Selector, @Algorithm, @PublicKeyBase64, @KeyLengthBits,
                     @Status, @CreatedUtc, @ModifiedUtc, @PublishedUtc, @ActivatedUtc,
                     @RetiredUtc, @SafeToDeleteAfterUtc)
                """,
                ToRow(key),
                ct)).ConfigureAwait(false);

            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO DkimPrivateKeys (DkimKeyId, ProtectedPrivateKey, CreatedUtc)
                VALUES (@DkimKeyId, @ProtectedPrivateKey, @CreatedUtc)
                """,
                new
                {
                    DkimKeyId = key.Id.Value,
                    ProtectedPrivateKey = protectedPrivateKey,
                    CreatedUtc = clock.UtcNow,
                },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task UpdateAsync(DkimKey key, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);

        return ExecuteAsync(async (session, ct) =>
        {
            // Selector, algorithm, public key and key length never change after generation - a
            // rotation is a new row, exactly as a certificate renewal is. Only the rotation
            // status and its timestamps are ever written back here.
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                UPDATE  DkimKeys
                SET     Status = @Status,
                        ModifiedUtc = @ModifiedUtc,
                        PublishedUtc = @PublishedUtc,
                        ActivatedUtc = @ActivatedUtc,
                        RetiredUtc = @RetiredUtc,
                        SafeToDeleteAfterUtc = @SafeToDeleteAfterUtc
                WHERE   Id = @Id
                """,
                ToRow(key),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task RemoveAsync(DkimKeyId id, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            // DkimPrivateKeys cascades from the FK, so removing the metadata row is enough.
            await session.Connection.ExecuteAsync(Command(
                session,
                "DELETE FROM DkimKeys WHERE Id = @Id",
                new { Id = id.Value },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);

    public Task<byte[]?> GetPrivateKeyAsync(DkimKeyId id, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            byte[]? protectedPrivateKey = await session.Connection
                .QuerySingleOrDefaultAsync<byte[]?>(Command(
                    session,
                    "SELECT ProtectedPrivateKey FROM DkimPrivateKeys WHERE DkimKeyId = @Id",
                    new { Id = id.Value },
                    ct))
                .ConfigureAwait(false);

            return protectedPrivateKey is null ? null : protector.Unprotect(protectedPrivateKey);
        }, cancellationToken);

    private static DkimKey Map(DkimKeyRow row) =>
        new(
            new DkimKeyId(row.Id),
            new DomainId(row.DomainId),
            DkimSelector.Parse(row.Selector),
            (DkimKeyAlgorithm)row.Algorithm,
            row.PublicKeyBase64,
            row.KeyLengthBits,
            (DkimKeyStatus)row.Status,
            row.CreatedUtc,
            row.ModifiedUtc,
            row.PublishedUtc,
            row.ActivatedUtc,
            row.RetiredUtc,
            row.SafeToDeleteAfterUtc);

    private static DkimKeyRow ToRow(DkimKey key) => new()
    {
        Id = key.Id.Value,
        DomainId = key.DomainId.Value,
        Selector = key.Selector.Value,
        Algorithm = (int)key.Algorithm,
        PublicKeyBase64 = key.PublicKeyBase64,
        KeyLengthBits = key.KeyLengthBits,
        Status = (int)key.Status,
        CreatedUtc = key.CreatedUtc,
        ModifiedUtc = key.ModifiedUtc,
        PublishedUtc = key.PublishedUtc,
        ActivatedUtc = key.ActivatedUtc,
        RetiredUtc = key.RetiredUtc,
        SafeToDeleteAfterUtc = key.SafeToDeleteAfterUtc,
    };
}
