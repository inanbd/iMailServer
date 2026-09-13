namespace MailServer.Admin.Services;

/// <summary>Settings for the administration application.</summary>
/// <remarks>
/// Deliberately small. The administration application holds almost no configuration of its
/// own because it holds almost no behaviour of its own: it needs to know which service to
/// talk to, and everything else is the service's business.
/// </remarks>
public sealed class AdminAppOptions
{
    public const string SectionName = "Admin";

    /// <summary>The machine hosting the service. "." is the local machine.</summary>
    public string ServerName { get; set; } = ".";

    public string PipeName { get; set; } = "AetherMail.Admin";

    public int MaxFrameBytes { get; set; } = 4 * 1024 * 1024;

    public int ConnectTimeoutMs { get; set; } = 5_000;

    public int RequestTimeoutSeconds { get; set; } = 60;

    /// <summary>How often the dashboard refreshes itself, in seconds.</summary>
    public int DashboardRefreshSeconds { get; set; } = 15;
}
