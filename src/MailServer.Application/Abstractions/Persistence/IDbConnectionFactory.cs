using System.Data.Common;

namespace MailServer.Application.Abstractions.Persistence;

/// <summary>
/// Opens connections to the configured database.
/// </summary>
/// <remarks>
/// Returns <see cref="DbConnection"/>, the provider-neutral BCL abstraction, so that nothing
/// above the persistence projects ever names <c>SqliteConnection</c> or
/// <c>SqlConnection</c>. Swapping providers is a configuration change, not a code change.
/// </remarks>
public interface IDbConnectionFactory
{
    /// <summary>
    /// Opens a new connection with every provider-specific setting already applied
    /// (WAL and busy-timeout pragmas for SQLite, encryption and retry settings for SQL
    /// Server). Callers receive a connection that is open and ready to use.
    /// </summary>
    Task<DbConnection> OpenConnectionAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// A description of the target safe to write to a log or show in the UI, with any
    /// credential removed. Never returns the raw connection string.
    /// </summary>
    string DescribeTarget();
}
