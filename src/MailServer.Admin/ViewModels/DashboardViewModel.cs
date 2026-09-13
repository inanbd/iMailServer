using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MailServer.Admin.Services;
using MailServer.Application.Monitoring.Dtos;
using MailServer.Domain.Enums;
using MailServer.Ipc.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Admin.ViewModels;

/// <summary>The dashboard: server health, counters and current operating mode.</summary>
public sealed partial class DashboardViewModel(
    IAdminGateway gateway,
    IOptions<AdminAppOptions> options,
    ILogger<DashboardViewModel> logger) : PageViewModel(logger), IDisposable
{
    private readonly AdminAppOptions _options = options.Value;
    private CancellationTokenSource? _refreshCancellation;
    private Task? _refreshLoop;

    public override string Title => "Dashboard";

    [ObservableProperty]
    public partial ServerCountersDto? Counters { get; set; }

    [ObservableProperty]
    public partial HealthState OverallHealth { get; set; } = HealthState.Unknown;

    [ObservableProperty]
    public partial MaintenanceMode MaintenanceMode { get; set; } = MaintenanceMode.Normal;

    [ObservableProperty]
    public partial string ServerHostname { get; set; } = "(not connected)";

    [ObservableProperty]
    public partial string DatabaseProvider { get; set; } = "-";

    [ObservableProperty]
    public partial string ProductVersion { get; set; } = "-";

    [ObservableProperty]
    public partial DateTimeOffset? LastRefreshedUtc { get; set; }

    public ObservableCollection<HealthComponentDto> Health { get; } = [];

    /// <summary>True when the server is not in Normal mode, so the shell can show a banner.</summary>
    public bool IsMaintenanceModeActive => MaintenanceMode != MaintenanceMode.Normal;

    [RelayCommand]
    private Task RefreshAsync() => LoadAsync();

    protected override async Task OnLoadAsync()
    {
        DashboardDto dashboard = await gateway.GetDashboardAsync().ConfigureAwait(true);

        Counters = dashboard.Counters;
        OverallHealth = dashboard.OverallHealth;
        MaintenanceMode = dashboard.MaintenanceMode;
        ServerHostname = dashboard.ServerHostname;
        DatabaseProvider = dashboard.DatabaseProvider;
        ProductVersion = dashboard.ProductVersion;
        LastRefreshedUtc = dashboard.GeneratedUtc;

        // Replace rather than rebind: the DataGrid keeps its scroll position and selection
        // when the collection is updated in place, which matters on a page that refreshes
        // itself every few seconds while an operator is reading it.
        Health.Clear();
        foreach (HealthComponentDto component in dashboard.Health)
        {
            Health.Add(component);
        }

        OnPropertyChanged(nameof(IsMaintenanceModeActive));

        StartAutoRefresh();
    }

    /// <summary>
    /// Starts the periodic refresh.
    /// </summary>
    /// <remarks>
    /// A <see cref="PeriodicTimer"/> loop rather than a <c>DispatcherTimer</c>, because the
    /// work is asynchronous I/O and the loop awaits each refresh before scheduling the next.
    /// A dispatcher timer would happily start a second refresh while the first was still in
    /// flight, and the IPC client would then serialise them into a growing backlog.
    /// </remarks>
    private void StartAutoRefresh()
    {
        if (_refreshLoop is not null)
        {
            return;
        }

        _refreshCancellation = new CancellationTokenSource();
        CancellationToken token = _refreshCancellation.Token;

        _refreshLoop = Task.Run(async () =>
        {
            using PeriodicTimer timer = new(
                TimeSpan.FromSeconds(Math.Clamp(_options.DashboardRefreshSeconds, 5, 300)));

            while (await timer.WaitForNextTickAsync(token).ConfigureAwait(false))
            {
                try
                {
                    DashboardDto dashboard = await gateway
                        .GetDashboardAsync(token)
                        .ConfigureAwait(false);

                    ApplyOnUiThread(dashboard);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    // A failed background refresh must not blank the dashboard or pop an
                    // error over whatever the operator is reading. The stale data plus a
                    // visibly old timestamp is more useful than an empty page.
                    logger.LogDebug(ex, "Background dashboard refresh failed.");
                }
            }
        }, token);
    }

    private void ApplyOnUiThread(DashboardDto dashboard)
    {
        System.Windows.Application.Current?.Dispatcher.Invoke(() =>
        {
            Counters = dashboard.Counters;
            OverallHealth = dashboard.OverallHealth;
            MaintenanceMode = dashboard.MaintenanceMode;
            LastRefreshedUtc = dashboard.GeneratedUtc;

            Health.Clear();
            foreach (HealthComponentDto component in dashboard.Health)
            {
                Health.Add(component);
            }

            OnPropertyChanged(nameof(IsMaintenanceModeActive));
        });
    }

    public void Dispose()
    {
        _refreshCancellation?.Cancel();
        _refreshCancellation?.Dispose();
        _refreshCancellation = null;
        _refreshLoop = null;
    }
}
