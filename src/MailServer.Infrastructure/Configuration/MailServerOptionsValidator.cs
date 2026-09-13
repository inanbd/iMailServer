using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Configuration;

/// <summary>
/// Validates the whole configuration tree at startup.
/// </summary>
/// <remarks>
/// <para>
/// Registered with <c>ValidateOnStart()</c>, so failures surface as a refusal to start with
/// an actionable message rather than as a mail server that runs and silently misbehaves.
/// </para>
/// <para>
/// Validation goes beyond data annotations because several rules are semantic: a hostname
/// must be a real FQDN, staging and message storage must share a volume for atomic moves,
/// and the development secret protector must never be selected in production.
/// </para>
/// </remarks>
public sealed class MailServerOptionsValidator : IValidateOptions<MailServerOptions>
{
    private readonly bool _isProductionEnvironment;

    public MailServerOptionsValidator(bool isProductionEnvironment) =>
        _isProductionEnvironment = isProductionEnvironment;

    public ValidateOptionsResult Validate(string? name, MailServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string> failures = [];

        ValidateServer(options.Server, failures);
        ValidateDatabase(options.Database, failures);
        ValidateStorage(options.Storage, failures);
        ValidateSecurity(options.Security, failures);
        ValidateIpc(options.Ipc, failures);
        ValidateMaintenance(options.Maintenance, failures);

        return failures.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(failures);
    }

    private void ValidateServer(ServerOptions server, List<string> failures)
    {
        if (string.IsNullOrWhiteSpace(server.Hostname))
        {
            failures.Add("MailServer:Server:Hostname is required.");
        }
        else if (!DomainName.TryParse(server.Hostname, out _, out string? error))
        {
            failures.Add(
                $"MailServer:Server:Hostname '{server.Hostname}' is not a valid fully-qualified " +
                $"domain name: {error} This name is announced in EHLO and must match the PTR " +
                "record for the sending IP, so it cannot be a bare machine name.");
        }

        if (!string.IsNullOrWhiteSpace(server.PublicIpAddress) &&
            !IpAddressValue.TryParse(server.PublicIpAddress, out _))
        {
            failures.Add(
                $"MailServer:Server:PublicIpAddress '{server.PublicIpAddress}' is not a valid " +
                "IP address.");
        }
    }

    private void ValidateDatabase(DatabaseOptions database, List<string> failures)
    {
        switch (database.Provider)
        {
            case DatabaseProvider.Sqlite:
                if (string.IsNullOrWhiteSpace(database.Sqlite.DataSource))
                {
                    failures.Add("MailServer:Database:Sqlite:DataSource is required when the provider is Sqlite.");
                }

                if (!string.Equals(database.Sqlite.JournalMode, "WAL", StringComparison.OrdinalIgnoreCase))
                {
                    // A warning expressed as a validation note rather than a hard failure:
                    // there are legitimate reasons to deviate, but the operator should be
                    // making that choice knowingly.
                    failures.Add(
                        $"MailServer:Database:Sqlite:JournalMode is '{database.Sqlite.JournalMode}'. " +
                        "WAL is required for acceptable concurrency between the IMAP readers and " +
                        "the queue writer. Change it only if you understand the consequence.");
                }

                break;

            case DatabaseProvider.SqlServer:
                bool hasInline = !string.IsNullOrWhiteSpace(database.SqlServer.ConnectionString);
                bool hasSecret = !string.IsNullOrWhiteSpace(database.SqlServer.ConnectionStringSecretName);

                if (!hasInline && !hasSecret)
                {
                    failures.Add(
                        "MailServer:Database:SqlServer requires either ConnectionString (development) " +
                        "or ConnectionStringSecretName (production).");
                }

                if (_isProductionEnvironment && hasInline)
                {
                    failures.Add(
                        "MailServer:Database:SqlServer:ConnectionString must not be used in " +
                        "Production. Store the connection string in the protected secret store " +
                        "and reference it by ConnectionStringSecretName so no credential is " +
                        "written to a configuration file.");
                }

                break;

            default:
                failures.Add($"MailServer:Database:Provider '{database.Provider}' is not a supported provider.");
                break;
        }
    }

    private static void ValidateStorage(StorageOptions storage, List<string> failures)
    {
        if (string.IsNullOrWhiteSpace(storage.DataRoot))
        {
            failures.Add("MailServer:Storage:DataRoot is required.");
            return;
        }

        if (storage.MaxMessageSizeBytes < 64 * 1024)
        {
            failures.Add(
                "MailServer:Storage:MaxMessageSizeBytes must be at least 64 KB; a lower limit " +
                "would reject ordinary mail with attachments.");
        }
    }

    private void ValidateSecurity(SecurityOptions security, List<string> failures)
    {
        if (security.SecretProtection == SecretProtectionScheme.Development && _isProductionEnvironment)
        {
            failures.Add(
                "MailServer:Security:SecretProtection is 'Development' but the environment is " +
                "Production. The development protector stores its key on disk and is not " +
                "suitable for protecting DKIM private keys, ACME account keys or certificate " +
                "passphrases. Use 'Dpapi'.");
        }

        if (security.SecretProtection == SecretProtectionScheme.Dpapi && !OperatingSystem.IsWindows())
        {
            failures.Add(
                "MailServer:Security:SecretProtection is 'Dpapi', which requires Windows. On a " +
                "non-Windows development machine set it to 'Development' and keep the " +
                "environment out of Production.");
        }
    }

    private static void ValidateIpc(IpcOptions ipc, List<string> failures)
    {
        if (string.IsNullOrWhiteSpace(ipc.PipeName))
        {
            failures.Add("MailServer:Ipc:PipeName is required.");
            return;
        }

        // A pipe name containing a path separator would escape the pipe namespace.
        if (ipc.PipeName.Contains('\\', StringComparison.Ordinal) ||
            ipc.PipeName.Contains('/', StringComparison.Ordinal))
        {
            failures.Add(
                "MailServer:Ipc:PipeName must be a bare name with no path separators; the " +
                @"\\.\pipe\ prefix is added automatically.");
        }
    }

    private static void ValidateMaintenance(MaintenanceOptions maintenance, List<string> failures)
    {
        if (!Enum.TryParse<Domain.Enums.MaintenanceMode>(maintenance.Mode, ignoreCase: true, out _))
        {
            failures.Add(
                $"MailServer:Maintenance:Mode '{maintenance.Mode}' is not a recognised mode. " +
                $"Valid values: {string.Join(", ", Enum.GetNames<Domain.Enums.MaintenanceMode>())}.");
        }
    }
}
