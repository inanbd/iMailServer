using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Threading;
using MailServer.Admin.Services;
using MailServer.Admin.ViewModels;
using MailServer.Admin.Views;
using MailServer.Ipc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;

namespace MailServer.Admin;

/// <summary>
/// The administration application's composition root.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is a management console, not the server.</b> Closing it, uninstalling it or
/// leaving it locked has no effect on mail flow: SMTP, IMAP, the outbound queue, certificate
/// renewal and every scheduled task run in the Windows Service.
/// </para>
/// <para>
/// The container here holds no database registration at all, because
/// <c>MailServer.Admin</c> does not reference a persistence project. Every operation goes
/// over the ACL-restricted named pipe to the service.
/// </para>
/// </remarks>
public partial class App : System.Windows.Application
{
    // Fully qualified: within the MailServer.* namespaces, a bare `Application` binds to the
    // MailServer.Application namespace rather than System.Windows.Application.

    private IHost? _host;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        try
        {
            _host = BuildHost();
            await _host.StartAsync().ConfigureAwait(true);

            MainWindow window = _host.Services.GetRequiredService<MainWindow>();
            MainWindow = window;
            window.Show();
        }
        catch (Exception ex)
        {
            // Nothing has been shown yet, so there is no UI to route this through. A message
            // box is the only way the administrator learns why the console did not open.
            MessageBox.Show(
                $"The administration application could not start.\n\n{ex.Message}",
                "AetherMail Server",
                MessageBoxButton.OK,
                MessageBoxImage.Error);

            Shutdown(1);
        }
    }

    private static IHost BuildHost()
    {
        HostApplicationBuilder builder = Host.CreateApplicationBuilder();

        builder.Configuration
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
            .AddEnvironmentVariables("AETHERMAIL_ADMIN_");

        AdminAppOptions options = builder.Configuration
            .GetSection(AdminAppOptions.SectionName)
            .Get<AdminAppOptions>() ?? new AdminAppOptions();

        builder.Services.Configure<AdminAppOptions>(
            builder.Configuration.GetSection(AdminAppOptions.SectionName));

        ConfigureLogging(builder);

        // The IPC client and the typed gateway. This is the whole of the admin
        // application's access to the server.
        builder.Services.AddIpcClient(o =>
        {
            o.ServerName = options.ServerName;
            o.PipeName = options.PipeName;
            o.MaxFrameBytes = options.MaxFrameBytes;
            o.ConnectTimeoutMs = options.ConnectTimeoutMs;
            o.RequestTimeoutSeconds = options.RequestTimeoutSeconds;
        });

        builder.Services.AddSingleton<INavigationService, NavigationService>();
        builder.Services.AddSingleton<ShellViewModel>();
        builder.Services.AddSingleton<MainWindow>();

        // Pages are transient so each visit starts with fresh state. An administration
        // console showing counts from the last time a page was open is worse than a reload.
        builder.Services.AddTransient<DashboardViewModel>();
        builder.Services.AddTransient<DomainsViewModel>();

        return builder.Build();
    }

    private static void ConfigureLogging(HostApplicationBuilder builder)
    {
        // The admin application's log lives under the user's own profile, not under the
        // service's data root: the service account owns that directory, and an interactive
        // administrator may not be able to write there.
        string logDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "AetherMail",
            "Logs");

        Directory.CreateDirectory(logDirectory);

        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .Enrich.FromLogContext()
            .Enrich.WithProperty("Application", "AetherMail.Admin")
            .WriteTo.File(
                Path.Combine(logDirectory, "admin-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 7,
                formatProvider: CultureInfo.InvariantCulture)
            .CreateLogger();

        builder.Logging.ClearProviders();
        builder.Services.AddSerilog(Log.Logger, dispose: false);
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        if (_host is not null)
        {
            await _host.StopAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(true);
            _host.Dispose();
        }

        await Log.CloseAndFlushAsync().ConfigureAwait(true);

        base.OnExit(e);
    }

    /// <summary>
    /// Last-resort handler for an exception that escaped a view model.
    /// </summary>
    /// <remarks>
    /// The exception is marked handled so the console stays open. An administration tool that
    /// vanishes mid-operation leaves the operator with no idea whether the operation was
    /// applied, which is a worse outcome than a dialog.
    /// </remarks>
    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Log.Error(e.Exception, "An unhandled exception reached the UI dispatcher.");

        MessageBox.Show(
            $"An unexpected error occurred.\n\n{e.Exception.Message}",
            "AetherMail Server",
            MessageBoxButton.OK,
            MessageBoxImage.Error);

        e.Handled = true;
    }
}
