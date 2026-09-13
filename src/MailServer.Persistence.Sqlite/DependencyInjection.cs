using MailServer.Application.Abstractions.Persistence;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace MailServer.Persistence.Sqlite;

/// <summary>Registers the SQLite provider.</summary>
public static class DependencyInjection
{
    /// <summary>
    /// Registers the SQLite connection factory and dialect.
    /// </summary>
    /// <remarks>
    /// Called by the composition root only when <c>Database:Provider</c> is <c>Sqlite</c>.
    /// Nothing else in the product references this assembly, which is what keeps a provider
    /// swap to one decision in one place.
    /// </remarks>
    public static IServiceCollection AddSqlitePersistence(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<ISqlDialect, SqliteDialect>();

        // Singleton: the factory itself is stateless and holds only the connection string.
        // The connections it hands out are short-lived and owned by their callers.
        services.TryAddSingleton<IDbConnectionFactory, SqliteConnectionFactory>();

        return services;
    }
}
