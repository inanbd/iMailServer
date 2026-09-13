using System.Globalization;
using MailServer.Application;
using MailServer.Infrastructure;
using MailServer.Infrastructure.Configuration;
using MailServer.Ipc;
using MailServer.Persistence.Sqlite;
using MailServer.Persistence.SqlServer;
using MailServer.Service.Bootstrap;
using MailServer.Service.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;

namespace MailServer.Service;

/// <summary>
/// The AetherMail Server composition root.
/// </summary>
/// <remarks>
/// <para>
/// <b>This process is the mail server.</b> The WPF administration application is a management
/// console; closing it, uninstalling it or leaving it locked has no effect on mail flow.
/// Every listener, queue, timer and certificate is owned here.
/// </para>
/// </remarks>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        // A bootstrap logger, before configuration is read, so that a failure while READING
        // configuration is still reported somewhere. Without it, the most common startup
        // failure of all - malformed appsettings.json - produces a silent exit.
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .WriteTo.Console(formatProvider: CultureInfo.InvariantCulture)
            .CreateBootstrapLogger();

        try
        {
            IHost host = BuildHost(args);

            Log.Information("AetherMail Server starting.");

            await host.RunAsync().ConfigureAwait(false);

            Log.Information("AetherMail Server stopped.");
            return 0;
        }
        catch (Exception ex)
        {
            // The host refuses to start on invalid configuration, a failed migration or
            // schema drift. All three are deliberate, and all three must say why before the
            // process exits - an operator watching a service fail to start has nothing else
            // to go on.
            Log.Fatal(ex, "AetherMail Server failed to start.");
            return 1;
        }
        finally
        {
            await Log.CloseAndFlushAsync().ConfigureAwait(false);
        }
    }

    /// <summary>Builds the host. Separated from <see cref="Main"/> so tests can build it too.</summary>
    public static IHost BuildHost(string[] args)
    {
        HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);

        // ---- Configuration -------------------------------------------------------------
        // ProgramData sits between the shipped defaults and environment variables: it is
        // where the installer writes machine configuration, and it must survive an upgrade
        // that replaces the files in Program Files.
        string machineConfigPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "AetherMail",
            "appsettings.machine.json");

        builder.Configuration
            .AddJsonFile(machineConfigPath, optional: true, reloadOnChange: false)
            .AddEnvironmentVariables("AETHERMAIL_")
            .AddCommandLine(args);

        bool isProduction = builder.Environment.IsProduction();

        // ---- Windows Service integration -----------------------------------------------
        // A no-op unless the process was actually launched by the Service Control Manager,
        // so the same binary runs as a console application for development and integration
        // testing without a second code path.
        builder.Services.AddWindowsService(o => o.ServiceName = "AetherMailServer");

        if (WindowsServiceHelpers.IsWindowsService())
        {
            // The SCM gives a service no working directory of its own; it inherits
            // system32. Relative paths in configuration would then resolve there, which is
            // both wrong and, for a data root, a genuine problem.
            Directory.SetCurrentDirectory(AppContext.BaseDirectory);
        }

        ConfigureSerilog(builder);

        // ---- Layers --------------------------------------------------------------------
        builder.Services.AddApplication();
        builder.Services.AddInfrastructure(builder.Configuration, isProduction);

        AddDatabaseProvider(builder);

        // ---- IPC ------------------------------------------------------------------------
        IpcOptions ipcOptions = builder.Configuration
            .GetSection($"{MailServerOptions.SectionName}:Ipc")
            .Get<IpcOptions>() ?? new IpcOptions();

        builder.Services.AddIpcServer(o =>
        {
            o.PipeName = ipcOptions.PipeName;
            o.MaxFrameBytes = ipcOptions.MaxFrameBytes;
            o.MaxConcurrentConnections = ipcOptions.MaxConcurrentConnections;
            o.RequestTimeoutSeconds = ipcOptions.RequestTimeoutSeconds;
        });

        // ---- Hosted services -------------------------------------------------------------
        // ORDER MATTERS. The host starts hosted services in registration order and awaits
        // each StartAsync, so registering the bootstrap gate first is what guarantees that
        // storage is ready and the schema is migrated before anything else runs. Later
        // milestones add their listeners and processors after this line, never before it.
        builder.Services.AddHostedService<DatabaseBootstrapService>();
        builder.Services.AddHostedService<ServiceHealthMonitor>();

        return builder.Build();
    }

    /// <summary>
    /// Selects the database provider from configuration.
    /// </summary>
    /// <remarks>
    /// The single place in the product where a provider is chosen. Everything above the
    /// persistence projects works through <c>IDbConnectionFactory</c> and <c>ISqlDialect</c>,
    /// so swapping providers is this one decision and a migration of the data.
    /// </remarks>
    private static void AddDatabaseProvider(HostApplicationBuilder builder)
    {
        DatabaseProvider provider = builder.Configuration
            .GetSection($"{MailServerOptions.SectionName}:Database:Provider")
            .Get<DatabaseProvider?>() ?? DatabaseProvider.Sqlite;

        switch (provider)
        {
            case DatabaseProvider.SqlServer:
                builder.Services.AddSqlServerPersistence();
                Log.Information("Database provider: Microsoft SQL Server.");
                break;

            case DatabaseProvider.Sqlite:
                builder.Services.AddSqlitePersistence();
                Log.Information("Database provider: SQLite.");
                break;

            default:
                throw new InvalidOperationException(
                    $"MailServer:Database:Provider is '{provider}', which is not a supported " +
                    $"provider. Valid values: {string.Join(", ", Enum.GetNames<DatabaseProvider>())}.");
        }
    }

    /// <summary>
    /// Configures structured logging.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Rolling daily files with a retention limit, because a mail server logs continuously and
    /// an unbounded log directory eventually fills the same volume the mail store is on.
    /// </para>
    /// <para>
    /// The console sink is added only when not running as a service: writing to a console
    /// that does not exist is wasted work on every log line.
    /// </para>
    /// </remarks>
    private static void ConfigureSerilog(HostApplicationBuilder builder)
    {
        StorageOptions storage = builder.Configuration
            .GetSection($"{MailServerOptions.SectionName}:Storage")
            .Get<StorageOptions>() ?? new StorageOptions();

        string logDirectory = Path.Combine(Path.GetFullPath(storage.DataRoot), "Logs");
        Directory.CreateDirectory(logDirectory);

        LoggerConfiguration configuration = new LoggerConfiguration()
            .ReadFrom.Configuration(builder.Configuration)
            .Enrich.FromLogContext()
            .Enrich.WithProperty("Application", "AetherMail.Service")
            .Enrich.WithProperty("MachineName", Environment.MachineName)

            // Microsoft's own informational logging is verbose and says nothing useful about
            // mail flow. Warnings and above still come through.
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
            .MinimumLevel.Override("System", LogEventLevel.Warning)

            .WriteTo.File(
                Path.Combine(logDirectory, "aethermail-.log"),
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 31,
                fileSizeLimitBytes: 256L * 1024 * 1024,
                rollOnFileSizeLimit: true,
                shared: false,
                formatProvider: CultureInfo.InvariantCulture,
                outputTemplate:
                    "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] " +
                    "({CorrelationId}) {SourceContext}: {Message:lj}{NewLine}{Exception}");

        if (!WindowsServiceHelpers.IsWindowsService())
        {
            configuration = configuration.WriteTo.Console(
                formatProvider: CultureInfo.InvariantCulture,
                outputTemplate:
                    "{Timestamp:HH:mm:ss} [{Level:u3}] {Message:lj}{NewLine}{Exception}");
        }

        Log.Logger = configuration.CreateLogger();

        builder.Logging.ClearProviders();
        builder.Services.AddSerilog(Log.Logger, dispose: false);
    }
}
