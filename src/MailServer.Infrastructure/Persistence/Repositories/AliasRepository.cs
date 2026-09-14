using Dapper;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Entities;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Persistence.Repositories;

/// <summary>Flat shape of an <c>Aliases</c> row.</summary>
internal sealed class AliasRow
{
    public Guid Id { get; set; }

    public Guid DomainId { get; set; }

    public string LocalPart { get; set; } = string.Empty;

    public string Address { get; set; } = string.Empty;

    public string Targets { get; set; } = string.Empty;

    public string? Description { get; set; }

    public bool IsEnabled { get; set; }

    public DateTimeOffset CreatedUtc { get; set; }

    public DateTimeOffset? ModifiedUtc { get; set; }
}

/// <summary>Persists aliases.</summary>
internal sealed class AliasRepository(
    IDbConnectionFactory connectionFactory,
    IAmbientDbSession ambientSession,
    ISqlDialect dialect)
    : SqlRepositoryBase(connectionFactory, ambientSession, dialect), IAliasRepository
{
    /// <summary>Separates targets in the denormalised column.</summary>
    /// <remarks>
    /// A newline, not a comma: an email address cannot contain either, but a newline keeps the
    /// column legible when an operator inspects the table, and comma-separated lists invite
    /// someone to split on ", " with a space and produce entries with leading blanks.
    /// </remarks>
    private const char TargetSeparator = '\n';

    private const string SelectColumns = """
        SELECT  Id, DomainId, LocalPart, Address, Targets, Description, IsEnabled, CreatedUtc,
                ModifiedUtc
        FROM    Aliases
        """;

    public Task<Alias?> GetAsync(AliasId id, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            AliasRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<AliasRow>(Command(
                    session,
                    SelectColumns + " WHERE Id = @Id",
                    new { Id = id.Value },
                    ct))
                .ConfigureAwait(false);

            return row is null ? null : Map(row);
        }, cancellationToken);

    public Task<Alias?> GetByAddressAsync(
        EmailAddress address,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);

        return ExecuteAsync(async (session, ct) =>
        {
            AliasRow? row = await session.Connection
                .QuerySingleOrDefaultAsync<AliasRow>(Command(
                    session,
                    SelectColumns + " WHERE Address = @Address",
                    new { Address = address.NormalizedValue },
                    ct))
                .ConfigureAwait(false);

            return row is null ? null : Map(row);
        }, cancellationToken);
    }

    public Task<bool> AddressExistsAsync(
        EmailAddress address,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);

        return ExecuteAsync(async (session, ct) =>
            await session.Connection.ExecuteScalarAsync<int>(Command(
                session,
                "SELECT COUNT(1) FROM Aliases WHERE Address = @Address",
                new { Address = address.NormalizedValue },
                ct)).ConfigureAwait(false) > 0,
            cancellationToken);
    }

    public Task<IReadOnlyList<Alias>> GetByDomainAsync(
        DomainId domainId,
        CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            IEnumerable<AliasRow> rows = await session.Connection
                .QueryAsync<AliasRow>(Command(
                    session,
                    SelectColumns + " WHERE DomainId = @DomainId ORDER BY Address",
                    new { DomainId = domainId.Value },
                    ct))
                .ConfigureAwait(false);

            return (IReadOnlyList<Alias>)rows.Select(Map).ToList();
        }, cancellationToken);

    /// <remarks>
    /// Loaded wholesale because expansion follows a graph, and a query per hop would turn one
    /// RCPT TO into several round trips. The alias count on a mail server is small and
    /// bounded — hundreds of rows, not the message table.
    /// </remarks>
    public Task<IReadOnlyList<Alias>> GetAllEnabledAsync(CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            IEnumerable<AliasRow> rows = await session.Connection
                .QueryAsync<AliasRow>(Command(
                    session,
                    SelectColumns + " WHERE IsEnabled = 1",
                    null,
                    ct))
                .ConfigureAwait(false);

            return (IReadOnlyList<Alias>)rows.Select(Map).ToList();
        }, cancellationToken);

    public Task AddAsync(Alias alias, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(alias);

        return ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                INSERT INTO Aliases
                    (Id, DomainId, LocalPart, Address, Targets, Description, IsEnabled,
                     CreatedUtc, ModifiedUtc)
                VALUES
                    (@Id, @DomainId, @LocalPart, @Address, @Targets, @Description, @IsEnabled,
                     @CreatedUtc, @ModifiedUtc)
                """,
                ToRow(alias),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task UpdateAsync(Alias alias, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(alias);

        return ExecuteAsync(async (session, ct) =>
        {
            // Address and DomainId are absent: the address is immutable, for the same reason a
            // mailbox's is. Changing it would silently redirect mail that correspondents are
            // still sending to the old name.
            await session.Connection.ExecuteAsync(Command(
                session,
                """
                UPDATE  Aliases
                SET     Targets = @Targets,
                        Description = @Description,
                        IsEnabled = @IsEnabled,
                        ModifiedUtc = @ModifiedUtc
                WHERE   Id = @Id
                """,
                ToRow(alias),
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);
    }

    public Task RemoveAsync(AliasId id, CancellationToken cancellationToken) =>
        ExecuteAsync(async (session, ct) =>
        {
            await session.Connection.ExecuteAsync(Command(
                session,
                "DELETE FROM Aliases WHERE Id = @Id",
                new { Id = id.Value },
                ct)).ConfigureAwait(false);

            return true;
        }, cancellationToken);

    // ---- Mapping ------------------------------------------------------------------------

    private static Alias Map(AliasRow row) =>
        new(
            new AliasId(row.Id),
            new DomainId(row.DomainId),
            EmailAddress.Parse(row.Address),
            ParseTargets(row.Targets),
            row.Description,
            row.IsEnabled,
            row.CreatedUtc,
            row.ModifiedUtc);

    /// <remarks>
    /// Unparseable entries are skipped rather than throwing. An alias row written by an older
    /// version whose address rules differed must still load: an unloadable alias breaks mail
    /// delivery for that address, whereas one with slightly fewer targets delivers to the rest.
    /// </remarks>
    private static List<EmailAddress> ParseTargets(string packed)
    {
        List<EmailAddress> targets = [];

        foreach (string entry in packed.Split(
                     TargetSeparator,
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (EmailAddress.TryParse(entry, out EmailAddress? parsed))
            {
                targets.Add(parsed);
            }
        }

        return targets;
    }

    private static AliasRow ToRow(Alias alias) => new()
    {
        Id = alias.Id.Value,
        DomainId = alias.DomainId.Value,
        LocalPart = alias.Address.LocalPart,
        Address = alias.Address.NormalizedValue,
        Targets = string.Join(
            TargetSeparator,
            alias.Targets.Select(static t => t.NormalizedValue)),
        Description = alias.Description,
        IsEnabled = alias.IsEnabled,
        CreatedUtc = alias.CreatedUtc,
        ModifiedUtc = alias.ModifiedUtc,
    };
}
