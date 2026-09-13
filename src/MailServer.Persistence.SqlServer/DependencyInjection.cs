using MailServer.Application.Abstractions.Persistence;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace MailServer.Persistence.SqlServer;

/// <summary>Registers the SQL Server provider.</summary>
public static class DependencyInjection
{
    /// <summary>
    /// Registers the SQL Server connection factory and dialect.
    /// </summary>
    /// <remarks>
    /// Called by the composition root only when <c>Database:Provider</c> is <c>SqlServer</c>.
    /// This is the recommended provider for production; see <c>docs/SqlServer.md</c>.
    /// </remarks>
    public static IServiceCollection AddSqlServerPersistence(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<ISqlDialect, SqlServerDialect>();
        services.TryAddSingleton<IDbConnectionFactory, SqlServerConnectionFactory>();

        return services;
    }
}
