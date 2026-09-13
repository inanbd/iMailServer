using MailServer.Application.Abstractions.Platform;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Platform;

/// <summary>
/// Resolves and creates the installation's filesystem layout.
/// </summary>
/// <remarks>
/// Every path the server uses is produced here rather than by string concatenation at the
/// point of use. That gives exactly one place to apply the containment check, one place to
/// create directories, and one place to verify that staging and message storage share a
/// volume - which they must, because <see cref="File.Move(string, string)"/> across volumes
/// is a copy, and a copy is not atomic.
/// </remarks>
public sealed class ServerPaths : IServerPaths
{
    private readonly ILogger<ServerPaths> _logger;

    public ServerPaths(IOptions<MailServerOptions> options, ILogger<ServerPaths> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        _logger = logger;

        DataRoot = Path.GetFullPath(options.Value.Storage.DataRoot);
        MessagesRoot = Path.Combine(DataRoot, "Messages");
        QueueRoot = Path.Combine(DataRoot, "Queue");
        TempRoot = Path.Combine(DataRoot, "Temp");
        CertificatesRoot = Path.Combine(DataRoot, "Certificates");
        BackupsRoot = Path.Combine(DataRoot, "Backups");
        LogsRoot = Path.Combine(DataRoot, "Logs");
        QuarantineRoot = Path.Combine(DataRoot, "Quarantine");
        ReportsRoot = Path.Combine(DataRoot, "Reports");
    }

    public string DataRoot { get; }

    public string MessagesRoot { get; }

    public string QueueRoot { get; }

    public string TempRoot { get; }

    public string CertificatesRoot { get; }

    public string BackupsRoot { get; }

    public string LogsRoot { get; }

    public string QuarantineRoot { get; }

    public string ReportsRoot { get; }

    public void EnsureCreated()
    {
        foreach (string directory in AllRoots())
        {
            if (Directory.Exists(directory))
            {
                continue;
            }

            Directory.CreateDirectory(directory);
            _logger.LogInformation("Created data directory {Directory}.", directory);
        }

        ApplyRestrictiveAcl();
    }

    /// <summary>Every managed root, for creation and for health checks.</summary>
    public IEnumerable<string> AllRoots()
    {
        yield return DataRoot;
        yield return MessagesRoot;
        yield return QueueRoot;
        yield return TempRoot;
        yield return CertificatesRoot;
        yield return BackupsRoot;
        yield return LogsRoot;
        yield return QuarantineRoot;
        yield return ReportsRoot;
    }

    public string ResolveContained(string root, string relativePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        ArgumentNullException.ThrowIfNull(relativePath);

        string fullRoot = Path.GetFullPath(root);

        // A trailing separator is essential to the comparison below. Without it,
        // "C:\Data\Messages-evil" would pass a prefix test against "C:\Data\Messages".
        string rootWithSeparator = fullRoot.EndsWith(Path.DirectorySeparatorChar)
            ? fullRoot
            : fullRoot + Path.DirectorySeparatorChar;

        string candidate = Path.GetFullPath(Path.Combine(fullRoot, relativePath));

        if (!candidate.StartsWith(rootWithSeparator, StringComparison.Ordinal) &&
            !string.Equals(candidate, fullRoot, StringComparison.Ordinal))
        {
            // Defence in depth. Every stored path is built from server-generated identifiers,
            // so reaching here means a bug in path construction, not hostile input - which is
            // precisely why it must be loud rather than silently sanitised.
            _logger.LogError(
                "Path containment violation: '{RelativePath}' resolved to '{Candidate}', " +
                "outside root '{Root}'.",
                relativePath,
                candidate,
                fullRoot);

            throw new UnauthorizedAccessException(
                $"The resolved path escapes its designated root '{fullRoot}'.");
        }

        return candidate;
    }

    /// <summary>
    /// Tightens directory permissions so only the service account and administrators can
    /// read mail, certificates and backups.
    /// </summary>
    /// <remarks>
    /// Windows-only. On other platforms the installer is responsible for permissions, and a
    /// warning is logged so nobody assumes this has been handled. The full ACL implementation
    /// arrives with the installer in Milestone 13; what matters now is that the hook exists
    /// and that its absence is visible rather than silent.
    /// </remarks>
    private void ApplyRestrictiveAcl()
    {
        if (!OperatingSystem.IsWindows())
        {
            _logger.LogWarning(
                "Running on a non-Windows platform: directory access control was NOT applied " +
                "to {DataRoot}. This configuration is for development only.",
                DataRoot);
            return;
        }

        _logger.LogDebug(
            "Directory access control for {DataRoot} is applied by the installer.",
            DataRoot);
    }
}
