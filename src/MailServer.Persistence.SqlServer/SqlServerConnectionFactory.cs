using System.Data.Common;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Security;
using MailServer.Infrastructure.Configuration;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Persistence.SqlServer;

/// <summary>
/// Opens SQL Server connections with secure defaults and built-in retry.
/// </summary>
/// <remarks>
/// <para>
/// <b>Encryption is forced on, and nothing here disables certificate validation.</b> Rule
/// 105 forbids certificate validation bypass, and that includes the database link: an
/// unencrypted or unvalidated connection carries every mailbox row and every audit record in
/// the clear. <c>Encrypt</c> is set to true unconditionally, overriding the operator's
/// connection string if it said otherwise.
/// </para>
/// <para>
/// <c>TrustServerCertificate</c> is never set by this code. It is only <i>read</i>, so that
/// an operator who put it in their own connection string gets a warning naming the exact
/// exposure it creates. Silently clearing it would be the wrong answer to a different
/// problem: the connection string is the operator's, a server with a genuinely
/// untrusted-but-correct certificate would simply stop connecting, and they would have no
/// idea why.
/// </para>
/// <para>
/// <b>The connection string is never logged.</b> <see cref="DescribeTarget"/> returns only
/// the server and database, built from the parsed builder so a credential cannot leak
/// through a string that happened to be formatted differently than expected.
/// </para>
/// </remarks>
public sealed class SqlServerConnectionFactory : IDbConnectionFactory
{
    private readonly string _connectionString;
    private readonly string _description;
    private readonly ILogger<SqlServerConnectionFactory> _logger;

    public SqlServerConnectionFactory(
        IOptions<MailServerOptions> options,
        ISecretProtector secretProtector,
        ILogger<SqlServerConnectionFactory> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(secretProtector);

        _logger = logger;

        SqlServerOptions sqlOptions = options.Value.Database.SqlServer;
        string raw = ResolveConnectionString(sqlOptions, secretProtector);

        SqlConnectionStringBuilder builder = new(raw)
        {
            // Retry the initial connect, not just commands. A SQL Server restart or an
            // Azure SQL failover should produce a brief pause, not a cascade of failures.
            ConnectRetryCount = Math.Clamp(sqlOptions.MaxRetryAttempts, 1, 20),
            ConnectRetryInterval = 5,
            CommandTimeout = sqlOptions.CommandTimeoutSeconds,

            ApplicationName = "AetherMail Server",

            // Pooling on: a mail server opens and closes connections constantly, and the
            // TLS handshake per connect would otherwise dominate.
            Pooling = true,
            MinPoolSize = 2,
            MaxPoolSize = 200,

            Encrypt = true,
        };

        if (builder.TrustServerCertificate)
        {
            _logger.LogWarning(
                "The SQL Server connection has TrustServerCertificate enabled. The link is " +
                "encrypted but the server's identity is NOT verified, so it is vulnerable to " +
                "an active man-in-the-middle. Install a certificate the service account " +
                "trusts and remove this setting.");
        }

        _connectionString = builder.ToString();
        _description = $"SQL Server '{builder.DataSource}', database '{builder.InitialCatalog}'";
    }

    public async Task<DbConnection> OpenConnectionAsync(CancellationToken cancellationToken = default)
    {
        SqlConnection connection = new(_connectionString);

        try
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    /// <summary>Server and database only. Never the credential.</summary>
    public string DescribeTarget() => _description;

    private static string ResolveConnectionString(
        SqlServerOptions options,
        ISecretProtector secretProtector)
    {
        // The protected secret store takes precedence, so a development connection string
        // left in appsettings cannot silently override the production credential.
        if (!string.IsNullOrWhiteSpace(options.ConnectionStringSecretName))
        {
            string protectedValue = SecretStore.Read(options.ConnectionStringSecretName)
                ?? throw new InvalidOperationException(
                    $"The connection string secret '{options.ConnectionStringSecretName}' was " +
                    "not found in the protected secret store. Create it with the " +
                    "administration application before starting the service.");

            return secretProtector.UnprotectString(protectedValue);
        }

        if (!string.IsNullOrWhiteSpace(options.ConnectionString))
        {
            return options.ConnectionString;
        }

        throw new InvalidOperationException(
            "No SQL Server connection string is configured. Set either " +
            "MailServer:Database:SqlServer:ConnectionStringSecretName (production) or " +
            "MailServer:Database:SqlServer:ConnectionString (development).");
    }
}

/// <summary>
/// Placeholder accessor for the protected secret store.
/// </summary>
/// <remarks>
/// The secret store lands in Milestone 2 alongside the master password and DPAPI key
/// management. It is a distinct seam from <see cref="ISecretProtector"/>: the protector
/// encrypts and decrypts, while the store decides where protected bytes live and who may
/// read them. Until Milestone 2 this returns null, so an installation configured to read the
/// connection string from the store fails to start with a clear message rather than falling
/// back to an unprotected value.
/// </remarks>
internal static class SecretStore
{
    public static string? Read(string secretName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secretName);
        return null;
    }
}
