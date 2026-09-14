using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Persistence.Repositories;

/// <summary>Flat shape of an <c>AcmeAccounts</c> row.</summary>
internal sealed class AcmeAccountRow
{
    public Guid Id { get; set; }

    public int Directory { get; set; }

    public string DirectoryUrl { get; set; } = string.Empty;

    public string? AccountUrl { get; set; }

    public string ContactEmail { get; set; } = string.Empty;

    public string AccountKeySecretName { get; set; } = string.Empty;

    public string? TermsAccepted { get; set; }

    public DateTimeOffset? TermsAcceptedUtc { get; set; }

    public bool IsActive { get; set; }

    public DateTimeOffset CreatedUtc { get; set; }

    public DateTimeOffset? ModifiedUtc { get; set; }
}

/// <summary>Flat shape of an <c>AcmeOrders</c> row.</summary>
internal sealed class AcmeOrderRow
{
    public Guid Id { get; set; }

    public Guid AccountId { get; set; }

    public string Identifiers { get; set; } = string.Empty;

    public string IdentifierSetKey { get; set; } = string.Empty;

    public string RegisteredDomain { get; set; } = string.Empty;

    public int ChallengeType { get; set; }

    public int Status { get; set; }

    public string? OrderUrl { get; set; }

    public Guid? IssuedCertificateId { get; set; }

    public string? LastError { get; set; }

    public int AttemptCount { get; set; }

    public DateTimeOffset? LastAttemptUtc { get; set; }

    public DateTimeOffset? CompletedUtc { get; set; }

    public DateTimeOffset CreatedUtc { get; set; }

    public DateTimeOffset? ModifiedUtc { get; set; }
}

/// <summary>Persists ACME accounts and the issuance history the rate limiter depends on.</summary>
internal sealed class AcmeRepository(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), IAcmeRepository
{
    private const char IdentifierSeparator = '\n';

    private const string SelectAccountColumns = """
        SELECT  Id, Directory, DirectoryUrl, AccountUrl, ContactEmail, AccountKeySecretName,
                TermsAccepted, TermsAcceptedUtc, IsActive, CreatedUtc, ModifiedUtc
        FROM    AcmeAccounts
        """;

    private const string SelectOrderColumns = """
        SELECT  Id, AccountId, Identifiers, IdentifierSetKey, RegisteredDomain, ChallengeType,
                Status, OrderUrl, IssuedCertificateId, LastError, AttemptCount, LastAttemptUtc,
                CompletedUtc, CreatedUtc, ModifiedUtc
        FROM    AcmeOrders
        """;

    // ---- Accounts -------------------------------------------------------------------------

    public Task<AcmeAccount?> GetAccountAsync(
        AcmeAccountId id,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            AcmeAccountRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<AcmeAccountRow>(Command(
                    session,
                    SelectAccountColumns + " WHERE Id = @Id",
                    new { Id = id.Value },
                    ct))
                .ConfigureAwait(false);

            return row is null ? null : Map(row);
        }, cancellationToken);

    public Task<AcmeAccount?> GetActiveAccountAsync(
        AcmeDirectory directory,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            AcmeAccountRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<AcmeAccountRow>(Command(
                    session,
                    SelectAccountColumns + " WHERE Directory = @Directory AND IsActive = 1",
                    new { Directory = (int)directory },
                    ct))
                .ConfigureAwait(false);

            return row is null ? null : Map(row);
        }, cancellationToken);

    public Task<IReadOnlyList<AcmeAccount>> GetAccountsAsync(CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            IEnumerable<AcmeAccountRow> rows = await session.Connection
                .QueryAsync<AcmeAccountRow>(Command(
                    session,
                    SelectAccountColumns + " ORDER BY CreatedUtc DESC",
                    null,
                    ct))
                .ConfigureAwait(false);

            return (IReadOnlyList<AcmeAccount>)rows.Select(Map).ToList();
        }, cancellationToken);

    public Task AddAccountAsync(AcmeAccount account, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(account);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO AcmeAccounts
                    (Id, Directory, DirectoryUrl, AccountUrl, ContactEmail,
                     AccountKeySecretName, TermsAccepted, TermsAcceptedUtc, IsActive,
                     CreatedUtc, ModifiedUtc)
                VALUES
                    (@Id, @Directory, @DirectoryUrl, @AccountUrl, @ContactEmail,
                     @AccountKeySecretName, @TermsAccepted, @TermsAcceptedUtc, @IsActive,
                     @CreatedUtc, @ModifiedUtc)
                """,
                ToRow(account),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task UpdateAccountAsync(AcmeAccount account, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(account);

        return ExecuteAsync(async (session, ct) =>
        {
            // The directory, its URL and the key secret name are not updatable: they are this
            // account's identity, and changing one in place would silently repoint a row at a
            // different registration - including the key that can revoke its certificates.
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                UPDATE  AcmeAccounts
                SET     AccountUrl = @AccountUrl,
                        ContactEmail = @ContactEmail,
                        TermsAccepted = @TermsAccepted,
                        TermsAcceptedUtc = @TermsAcceptedUtc,
                        IsActive = @IsActive,
                        ModifiedUtc = @ModifiedUtc
                WHERE   Id = @Id
                """,
                ToRow(account),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    // ---- Orders ---------------------------------------------------------------------------

    public Task<AcmeOrder?> GetOrderAsync(AcmeOrderId id, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            AcmeOrderRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<AcmeOrderRow>(Command(
                    session,
                    SelectOrderColumns + " WHERE Id = @Id",
                    new { Id = id.Value },
                    ct))
                .ConfigureAwait(false);

            return row is null ? null : MapOrder(row);
        }, cancellationToken);

    public Task<IReadOnlyList<AcmeOrder>> GetRecentOrdersAsync(
        int limit,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            IEnumerable<AcmeOrderRow> rows = await session.Connection
                .QueryAsync<AcmeOrderRow>(Command(
                    session,
                    SelectOrderColumns + " ORDER BY CreatedUtc DESC " +
                        Dialect.PagingClause(limit, 0),
                    null,
                    ct))
                .ConfigureAwait(false);

            return (IReadOnlyList<AcmeOrder>)rows.Select(MapOrder).ToList();
        }, cancellationToken);

    public Task AddOrderAsync(
        AcmeOrder order,
        string registeredDomain,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(order);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO AcmeOrders
                    (Id, AccountId, Identifiers, IdentifierSetKey, RegisteredDomain,
                     ChallengeType, Status, OrderUrl, IssuedCertificateId, LastError,
                     AttemptCount, LastAttemptUtc, CompletedUtc, CreatedUtc, ModifiedUtc)
                VALUES
                    (@Id, @AccountId, @Identifiers, @IdentifierSetKey, @RegisteredDomain,
                     @ChallengeType, @Status, @OrderUrl, @IssuedCertificateId, @LastError,
                     @AttemptCount, @LastAttemptUtc, @CompletedUtc, @CreatedUtc, @ModifiedUtc)
                """,
                ToOrderRow(order, registeredDomain),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task UpdateOrderAsync(AcmeOrder order, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(order);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                UPDATE  AcmeOrders
                SET     Status = @Status,
                        OrderUrl = @OrderUrl,
                        IssuedCertificateId = @IssuedCertificateId,
                        LastError = @LastError,
                        AttemptCount = @AttemptCount,
                        LastAttemptUtc = @LastAttemptUtc,
                        CompletedUtc = @CompletedUtc,
                        ModifiedUtc = @ModifiedUtc
                WHERE   Id = @Id
                """,
                ToOrderRow(order, registeredDomain: string.Empty),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    /// <remarks>
    /// One round trip for all three counts, because this runs before every order and the counts
    /// are evaluated together.
    /// <para>
    /// <c>OrderUrl IS NOT NULL</c> on every clause is load-bearing: it restricts the counts to
    /// orders the CA actually saw. An order refused locally by pre-flight or by the limiter
    /// consumed no quota, and counting it would make the server progressively more reluctant to
    /// do something that has cost nothing — a limiter that ratchets itself shut.
    /// </para>
    /// </remarks>
    public Task<AcmeAttemptCounts> CountRecentAttemptsAsync(
        string registeredDomain,
        string identifierSetKey,
        DateTimeOffset weeklyWindowStart,
        DateTimeOffset failureWindowStart,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            AttemptCountRow row = await session.Connection
                .QuerySingleAsync<AttemptCountRow>(Command(
                    session,
                    $"""
                     SELECT
                        (SELECT COUNT(*) FROM AcmeOrders
                          WHERE RegisteredDomain = @RegisteredDomain
                            AND Status = {(int)AcmeOrderStatus.Valid}
                            AND OrderUrl IS NOT NULL
                            AND LastAttemptUtc >= @WeeklyStart)  AS ForRegisteredDomain,

                        (SELECT COUNT(*) FROM AcmeOrders
                          WHERE IdentifierSetKey = @SetKey
                            AND Status = {(int)AcmeOrderStatus.Valid}
                            AND OrderUrl IS NOT NULL
                            AND LastAttemptUtc >= @WeeklyStart)  AS Duplicates,

                        (SELECT COUNT(*) FROM AcmeOrders
                          WHERE IdentifierSetKey = @SetKey
                            AND Status = {(int)AcmeOrderStatus.Invalid}
                            AND OrderUrl IS NOT NULL
                            AND LastAttemptUtc >= @FailureStart) AS RecentFailures,

                        (SELECT MIN(LastAttemptUtc) FROM AcmeOrders
                          WHERE (IdentifierSetKey = @SetKey OR RegisteredDomain = @RegisteredDomain)
                            AND OrderUrl IS NOT NULL
                            AND LastAttemptUtc >= @WeeklyStart)  AS OldestAttemptUtc
                     """,
                    new
                    {
                        RegisteredDomain = registeredDomain,
                        SetKey = identifierSetKey,
                        WeeklyStart = weeklyWindowStart,
                        FailureStart = failureWindowStart,
                    },
                    ct))
                .ConfigureAwait(false);

            return new AcmeAttemptCounts(
                row.ForRegisteredDomain,
                row.Duplicates,
                row.RecentFailures,
                row.OldestAttemptUtc);
        }, cancellationToken);

    private sealed class AttemptCountRow
    {
        public int ForRegisteredDomain { get; set; }

        public int Duplicates { get; set; }

        public int RecentFailures { get; set; }

        public DateTimeOffset? OldestAttemptUtc { get; set; }
    }

    // ---- Mapping --------------------------------------------------------------------------

    private static AcmeAccount Map(AcmeAccountRow row) =>
        new(
            new AcmeAccountId(row.Id),
            (AcmeDirectory)row.Directory,
            row.DirectoryUrl,
            row.AccountUrl,
            row.ContactEmail,
            row.AccountKeySecretName,
            row.TermsAccepted,
            row.TermsAcceptedUtc,
            row.IsActive,
            row.CreatedUtc,
            row.ModifiedUtc);

    private static AcmeAccountRow ToRow(AcmeAccount account) => new()
    {
        Id = account.Id.Value,
        Directory = (int)account.Directory,
        DirectoryUrl = account.DirectoryUrl,
        AccountUrl = account.AccountUrl,
        ContactEmail = account.ContactEmail,
        AccountKeySecretName = account.AccountKeySecretName,
        TermsAccepted = account.TermsOfServiceAccepted,
        TermsAcceptedUtc = account.TermsAcceptedUtc,
        IsActive = account.IsActive,
        CreatedUtc = account.CreatedUtc,
        ModifiedUtc = account.ModifiedUtc,
    };

    private static AcmeOrder MapOrder(AcmeOrderRow row) =>
        new(
            new AcmeOrderId(row.Id),
            new AcmeAccountId(row.AccountId),
            ParseIdentifiers(row.Identifiers),
            (AcmeChallengeType)row.ChallengeType,
            (AcmeOrderStatus)row.Status,
            row.OrderUrl,
            row.IssuedCertificateId is { } certificateId
                ? new CertificateId(certificateId)
                : null,
            row.LastError,
            row.AttemptCount,
            row.LastAttemptUtc,
            row.CompletedUtc,
            row.CreatedUtc,
            row.ModifiedUtc);

    /// <remarks>
    /// Unparseable entries are skipped rather than throwing, for the same reason as the
    /// certificate repository: a row written by an older version must still load, and an
    /// unloadable order breaks the rate-limit history it exists to provide.
    /// </remarks>
    private static List<DomainName> ParseIdentifiers(string packed)
    {
        List<DomainName> identifiers = [];

        foreach (string entry in packed.Split(
                     IdentifierSeparator,
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (DomainName.TryParse(entry, out DomainName? parsed))
            {
                identifiers.Add(parsed);
            }
        }

        return identifiers;
    }

    private static AcmeOrderRow ToOrderRow(AcmeOrder order, string registeredDomain) => new()
    {
        Id = order.Id.Value,
        AccountId = order.AccountId.Value,
        Identifiers = string.Join(
            IdentifierSeparator,
            order.Identifiers.Select(static i => i.Value)),
        IdentifierSetKey = order.IdentifierSetKey,
        RegisteredDomain = registeredDomain,
        ChallengeType = (int)order.ChallengeType,
        Status = (int)order.Status,
        OrderUrl = order.OrderUrl,
        IssuedCertificateId = order.IssuedCertificateId?.Value,
        LastError = order.LastError,
        AttemptCount = order.AttemptCount,
        LastAttemptUtc = order.LastAttemptUtc,
        CompletedUtc = order.CompletedUtc,
        CreatedUtc = order.CreatedUtc,
        ModifiedUtc = order.ModifiedUtc,
    };
}
