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
public sealed partial class ShellViewModel : ObservableObject
{
    private readonly INavigationService _navigation;

    public ShellViewModel(INavigationService navigation)
    {
        ArgumentNullException.ThrowIfNull(navigation);

        _navigation = navigation;
        _navigation.Navigated += (_, page) => CurrentPage = page;

        NavigationEntries = BuildNavigationTree();
    }

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
        if (entry is null || !entry.IsAvailable)
        {
            return;
        }

        _navigation.NavigateTo(entry.ViewModelType);
    }

    /// <summary>Opens the default page.</summary>
    public void Start() => _navigation.NavigateTo<DashboardViewModel>();

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
        new("Mailboxes", "Mail", typeof(DomainsViewModel), IsAvailable: false),
        new("Aliases", "Mail", typeof(DomainsViewModel), IsAvailable: false),
        new("Queue", "Mail", typeof(DomainsViewModel), IsAvailable: false),
        new("Quarantine", "Mail", typeof(DomainsViewModel), IsAvailable: false),
        new("Message Trace", "Mail", typeof(DomainsViewModel), IsAvailable: false),

        new("Services", "Server", typeof(DashboardViewModel), IsAvailable: false),
        new("Network", "Server", typeof(DashboardViewModel), IsAvailable: false),
        new("Certificates", "Server", typeof(DashboardViewModel), IsAvailable: false),
        new("Storage", "Server", typeof(DashboardViewModel), IsAvailable: false),
        new("Database", "Server", typeof(DashboardViewModel), IsAvailable: false),

        new("Authentication", "Security", typeof(DashboardViewModel), IsAvailable: false),
        new("IP Rules", "Security", typeof(DashboardViewModel), IsAvailable: false),
        new("Rate Limits", "Security", typeof(DashboardViewModel), IsAvailable: false),
        new("Anti-Spam", "Security", typeof(DashboardViewModel), IsAvailable: false),
        new("Security Events", "Security", typeof(DashboardViewModel), IsAvailable: false),

        new("Overview", "Deliverability", typeof(DashboardViewModel), IsAvailable: false),
        new("DNS", "Deliverability", typeof(DashboardViewModel), IsAvailable: false),
        new("SPF", "Deliverability", typeof(DashboardViewModel), IsAvailable: false),
        new("DKIM", "Deliverability", typeof(DashboardViewModel), IsAvailable: false),
        new("DMARC", "Deliverability", typeof(DashboardViewModel), IsAvailable: false),
        new("MTA-STS", "Deliverability", typeof(DashboardViewModel), IsAvailable: false),
        new("TLS-RPT", "Deliverability", typeof(DashboardViewModel), IsAvailable: false),
        new("Delivery Test", "Deliverability", typeof(DashboardViewModel), IsAvailable: false),

        new("Statistics", "Monitoring", typeof(DashboardViewModel), IsAvailable: false),
        new("SMTP Sessions", "Monitoring", typeof(DashboardViewModel), IsAvailable: false),
        new("Logs", "Monitoring", typeof(DashboardViewModel), IsAvailable: false),

        new("Backups", "Maintenance", typeof(DashboardViewModel), IsAvailable: false),
        new("Database Migration", "Maintenance", typeof(DashboardViewModel), IsAvailable: false),
        new("Updates", "Maintenance", typeof(DashboardViewModel), IsAvailable: false),
    ];
}
