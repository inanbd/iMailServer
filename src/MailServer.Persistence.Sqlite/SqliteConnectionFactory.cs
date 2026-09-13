using System.Data.Common;
using System.Globalization;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Infrastructure.Configuration;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Persistence.Sqlite;

/// <summary>
/// Opens SQLite connections with every pragma applied.
/// </summary>
/// <remarks>
/// <para>
/// The pragmas are the whole point of this class. SQLite's defaults are wrong for a mail
/// server in three specific ways, and every one of them has to be corrected <b>per
/// connection</b> because connection pooling hands back connections that do not remember
/// session state:
/// </para>
/// <list type="bullet">
///   <item><description><b>journal_mode=WAL</b> - the default rollback journal makes readers
///   and the writer block each other. Under WAL an IMAP client can read while the queue
///   writes, which is the normal state of a working mail server.</description></item>
///   <item><description><b>busy_timeout</b> - without it, hitting the writer lock fails
///   instantly with SQLITE_BUSY instead of waiting the moment or two the writer needs.</description></item>
///   <item><description><b>foreign_keys=ON</b> - SQLite disables foreign keys by default,
///   per connection. A server that assumes referential integrity while the engine is not
///   enforcing it accumulates orphaned rows silently.</description></item>
/// </list>
/// <para>
/// <c>journal_mode</c> is persistent in the database file, but is set on every connection
/// anyway: it costs one cheap statement and guarantees the mode regardless of how the file
/// was created.
/// </para>
/// </remarks>
public sealed class SqliteConnectionFactory : IDbConnectionFactory
{
    private readonly SqliteOptions _options;
    private readonly string _connectionString;
    private readonly ILogger<SqliteConnectionFactory> _logger;

    public SqliteConnectionFactory(
        IOptions<MailServerOptions> options,
        ILogger<SqliteConnectionFactory> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options.Value.Database.Sqlite;
        _logger = logger;

        string dataSource = Path.GetFullPath(_options.DataSource);

        string? directory = Path.GetDirectoryName(dataSource);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = dataSource,
            Mode = SqliteOpenMode.ReadWriteCreate,

            // Shared cache is deliberately NOT used. It is a documented source of
            // hard-to-diagnose table-level locking errors, and WAL gives better concurrency
            // without it.
            Cache = SqliteCacheMode.Private,

            // Applied per connection as well; set here so a connection opened before the
            // pragma statements run still waits rather than failing.
            DefaultTimeout = Math.Max(1, _options.BusyTimeoutMs / 1000),

            Pooling = true,
        }.ToString();

        DataSourcePath = dataSource;
    }

    /// <summary>Absolute path of the database file.</summary>
    public string DataSourcePath { get; }

    public async Task<DbConnection> OpenConnectionAsync(CancellationToken cancellationToken = default)
    {
        SqliteConnection connection = new(_connectionString);

        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await ApplyPragmasAsync(connection, cancellationToken).ConfigureAwait(false);
            return connection;
        }
        catch
        {
            // Never leak a half-opened connection on a failure path; under pooling that
            // would eventually exhaust the pool and present as an unrelated hang.
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>The file path. There is no credential in a SQLite connection string to redact.</summary>
    public string DescribeTarget() => $"SQLite file '{DataSourcePath}'";

    private async Task ApplyPragmasAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        // Pragma values cannot be parameterised, so each one is validated against a closed
        // allow-list before it is interpolated. Configuration is trusted, but "trusted input
        // interpolated into SQL" is a habit worth never forming.
        string journalMode = ValidateEnum(
            _options.JournalMode,
            ["WAL", "DELETE", "TRUNCATE", "PERSIST", "MEMORY", "OFF"],
            nameof(SqliteOptions.JournalMode));

        string synchronous = ValidateEnum(
            _options.Synchronous,
            ["OFF", "NORMAL", "FULL", "EXTRA"],
            nameof(SqliteOptions.Synchronous));

        int busyTimeout = Math.Clamp(_options.BusyTimeoutMs, 0, 120_000);
        int cacheKb = Math.Clamp(_options.CacheSizeKilobytes, 64, 1_048_576);

        string pragmas = string.Create(
            CultureInfo.InvariantCulture,
            $"""
             PRAGMA journal_mode = {journalMode};
             PRAGMA synchronous = {synchronous};
             PRAGMA busy_timeout = {busyTimeout};
             PRAGMA foreign_keys = {(_options.EnforceForeignKeys ? "ON" : "OFF")};
             PRAGMA cache_size = -{cacheKb};
             PRAGMA temp_store = MEMORY;
             """);

        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = pragmas;

        try
        {
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (SqliteException ex)
        {
            // A pragma failure means the connection is not configured as the rest of the
            // system assumes. Surfacing it beats running with silently wrong concurrency
            // semantics and diagnosing SQLITE_BUSY storms later.
            _logger.LogError(ex, "Failed to apply SQLite pragmas to a new connection.");
            throw;
        }
    }

    private static string ValidateEnum(string value, string[] allowed, string settingName)
    {
        foreach (string candidate in allowed)
        {
            if (string.Equals(value, candidate, StringComparison.OrdinalIgnoreCase))
            {
                return candidate;
            }
        }

        throw new InvalidOperationException(
            $"MailServer:Database:Sqlite:{settingName} is '{value}', which is not one of: " +
            $"{string.Join(", ", allowed)}.");
    }
}
