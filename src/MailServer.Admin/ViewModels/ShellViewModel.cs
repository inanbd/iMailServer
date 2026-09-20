using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MailServer.Admin.Services;
using MailServer.Domain.Enums;

namespace MailServer.Admin.ViewModels;

/// <summary>One entry in the shell's navigation tree.</summary>
public sealed record NavigationEntry(string Title, string Group, Type ViewModelType, bool IsAvailable = true);

/// <summary>
/// The shell: navigation, connection state and the status strip.
/// </summary>
/// <remarks>
/// The navigation tree lists the full product structure from the start, with entries for
/// not-yet-implemented sections marked unavailable and shown greyed. That is deliberate: it
/// tells an operator what this product is going to be, and makes the delivery plan visible
/// rather than hiding it behind menus that appear one release at a time.
/// </remarks>
public sealed partial class ShellViewModel : ObservableObject, IDisposable
{
    private readonly INavigationService _navigation;
    private readonly IIdleMonitor _idleMonitor;

    public ShellViewModel(
        INavigationService navigation,
        AuthenticationViewModel authentication,
        IIdleMonitor idleMonitor)
    {
        ArgumentNullException.ThrowIfNull(navigation);
        ArgumentNullException.ThrowIfNull(authentication);
        ArgumentNullException.ThrowIfNull(idleMonitor);

        _navigation = navigation;
        _navigation.Navigated += (_, page) => CurrentPage = page;

        Authentication = authentication;
        _idleMonitor = idleMonitor;

        Authentication.Authenticated += OnAuthenticated;
        Authentication.SignedOut += OnSignedOut;

        // The idle timer is the client half of auto-lock. The server enforces the same timeout
        // on the session independently, so a client that simply declined to lock itself would
        // still find its next request refused - this half exists to clear the screen promptly,
        // not to be the control.
        _idleMonitor.IdleTimeoutElapsed += OnIdleTimeoutElapsed;

        NavigationEntries = BuildNavigationTree();
    }

    /// <summary>The authentication overlay. Gates everything else in the shell.</summary>
    public AuthenticationViewModel Authentication { get; }

    /// <summary>True when the shell's content should be visible.</summary>
    public bool IsUnlocked => Authentication.IsAuthenticated;

    [ObservableProperty]
    public partial PageViewModel? CurrentPage { get; set; }

    [ObservableProperty]
    public partial bool IsConnected { get; set; }

    [ObservableProperty]
    public partial string ConnectionStatus { get; set; } = "Connecting to the AetherMail service…";

    [ObservableProperty]
    public partial HealthState OverallHealth { get; set; } = HealthState.Unknown;

    [ObservableProperty]
    public partial MaintenanceMode MaintenanceMode { get; set; } = MaintenanceMode.Normal;

    public ObservableCollection<NavigationEntry> NavigationEntries { get; }

    [RelayCommand]
    private void Navigate(NavigationEntry? entry)
    {
        if (entry is null || !entry.IsAvailable || !IsUnlocked)
        {
            return;
        }

        _idleMonitor.RecordActivity();
        _navigation.NavigateTo(entry.ViewModelType);
    }

    /// <summary>Locks the console on request.</summary>
    [RelayCommand]
    private Task LockAsync() => Authentication.LockAsync(isAutoLock: false);

    /// <summary>Begins by asking the service whether setup is required.</summary>
    public Task StartAsync() => Authentication.InitializeAsync();

    /// <summary>Records user activity, resetting the idle timer.</summary>
    public void RecordActivity() => _idleMonitor.RecordActivity();

    private void OnAuthenticated(object? sender, EventArgs e)
    {
        OnPropertyChanged(nameof(IsUnlocked));

        _idleMonitor.Start(TimeSpan.FromSeconds(Authentication.IdleTimeoutSeconds));
        _navigation.NavigateTo<DashboardViewModel>();
    }

    private void OnSignedOut(object? sender, EventArgs e)
    {
        _idleMonitor.Stop();

        // Dispose the page before dropping it: the dashboard holds a background refresh loop
        // that would otherwise keep polling with a token the server has already rejected.
        if (CurrentPage is IDisposable disposable)
        {
            disposable.Dispose();
        }

        CurrentPage = null;
        OnPropertyChanged(nameof(IsUnlocked));
    }

    private void OnIdleTimeoutElapsed(object? sender, EventArgs e) =>
        _ = Authentication.LockAsync(isAutoLock: true);

    public void Dispose()
    {
        _idleMonitor.IdleTimeoutElapsed -= OnIdleTimeoutElapsed;
        Authentication.Authenticated -= OnAuthenticated;
        Authentication.SignedOut -= OnSignedOut;

        _idleMonitor.Dispose();

        if (CurrentPage is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }

    /// <summary>
    /// The full product navigation tree.
    /// </summary>
    /// <remarks>
    /// Entries marked unavailable are scheduled for later milestones and are shown disabled.
    /// The milestone each belongs to is in <c>docs/Architecture.md</c> §27.
    /// </remarks>
    private static ObservableCollection<NavigationEntry> BuildNavigationTree() =>
    [
        new("Dashboard", "Overview", typeof(DashboardViewModel)),

        new("Domains", "Mail", typeof(DomainsViewModel)),
        // One page, because mailboxes and aliases share an address space: an address is one or
        // the other, and deciding which to create is a single decision rather than a choice
        // between two screens.
        new("Mailboxes & Aliases", "Mail", typeof(MailboxesViewModel)),
        // Listeners and the received-mail log on one page: "is this server accepting mail" and
        // "did this message arrive" are the same question asked from two directions, and an
        // operator chasing a delivery needs both at once.
        new("SMTP", "Mail", typeof(SmtpViewModel)),
        new("Queue", "Mail", typeof(DomainsViewModel), IsAvailable: false),
        new("Quarantine", "Mail", typeof(DomainsViewModel), IsAvailable: false),
        new("Message Trace", "Mail", typeof(DomainsViewModel), IsAvailable: false),

        new("Services", "Server", typeof(DashboardViewModel), IsAvailable: false),
        new("Network", "Server", typeof(DashboardViewModel), IsAvailable: false),
        new("Certificates", "Server", typeof(CertificatesViewModel)),
        new("Let's Encrypt", "Server", typeof(LetsEncryptViewModel)),
        new("Storage", "Server", typeof(DashboardViewModel), IsAvailable: false),
        new("Database", "Server", typeof(DashboardViewModel), IsAvailable: false),

        new("Overview", "Security", typeof(SecurityViewModel)),
        new("Security Events", "Security", typeof(SecurityEventsViewModel)),
        new("Audit Log", "Security", typeof(AuditLogViewModel)),
        new("IP Rules", "Security", typeof(DashboardViewModel), IsAvailable: false),
        new("Rate Limits", "Security", typeof(DashboardViewModel), IsAvailable: false),
        new("Anti-Spam", "Security", typeof(DashboardViewModel), IsAvailable: false),

        // One entry rather than the eight this group was sketched with. SPF, DKIM, DMARC,
        // MTA-STS and TLS-RPT are checks inside the readiness report, not pages: giving each a
        // nav entry that opened the same report would be five ways to reach one thing, and
        // splitting the report five ways would scatter the evidence an operator is comparing.
        // The report, the DNS plan, the header analyser and the delivery test share a page
        // because they share a subject - the domain named at the top of it.
        new("Readiness", "Deliverability", typeof(DeliverabilityViewModel)),

        new("Statistics", "Monitoring", typeof(DashboardViewModel), IsAvailable: false),
        new("SMTP Sessions", "Monitoring", typeof(DashboardViewModel), IsAvailable: false),
        new("Logs", "Monitoring", typeof(DashboardViewModel), IsAvailable: false),

        new("Backups", "Maintenance", typeof(DashboardViewModel), IsAvailable: false),
        new("Database Migration", "Maintenance", typeof(DashboardViewModel), IsAvailable: false),
        new("Updates", "Maintenance", typeof(DashboardViewModel), IsAvailable: false),
    ];
}
