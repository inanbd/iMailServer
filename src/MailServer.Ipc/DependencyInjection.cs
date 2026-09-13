using MailServer.Application.Abstractions.Security;
using MailServer.Ipc.Client;
using MailServer.Ipc.Protocol;
using MailServer.Ipc.Server;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Ipc;

/// <summary>Registers the IPC server (service side) and client (admin side).</summary>
public static class DependencyInjection
{
    /// <summary>Adds the named-pipe IPC server. Called by the Windows Service host only.</summary>
    public static IServiceCollection AddIpcServer(
        this IServiceCollection services,
        Action<IpcServerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);

        // Singleton and built once at startup: the registry validates every entry in its
        // constructor, so a command missing its authorization declaration fails the service's
        // first second of life rather than shipping as an unauthenticated endpoint.
        services.TryAddSingleton<IpcCommandRegistry>();

        // Registered through explicit factories rather than by type. The dispatcher and the
        // caller-identity record are internal on purpose - they are implementation detail of
        // the server side, not part of the assembly's contract - and the container needs a
        // public constructor to activate a type by name. A factory keeps the encapsulation
        // and costs one lambda.
        services.TryAddSingleton(sp => new IpcRequestDispatcher(
            sp.GetRequiredService<IServiceScopeFactory>(),
            sp.GetRequiredService<IpcCommandRegistry>(),
            sp.GetRequiredService<IAdminSessionManager>(),
            sp.GetRequiredService<ILogger<IpcRequestDispatcher>>()));

        services.AddHostedService(sp => new IpcServerHostedService(
            sp.GetRequiredService<IOptions<IpcServerOptions>>(),
            sp.GetRequiredService<IpcRequestDispatcher>(),
            sp.GetRequiredService<ILogger<IpcServerHostedService>>()));

        return services;
    }

    /// <summary>Adds the IPC client and the typed gateway. Called by the WPF host only.</summary>
    public static IServiceCollection AddIpcClient(
        this IServiceCollection services,
        Action<IpcClientOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        IpcClientOptions options = new();
        configure(options);

        // Singleton: one pipe, one conversation. The client serialises requests internally,
        // and a pool of pipes would gain nothing for an administration console while making
        // request/response correlation harder to reason about.
        services.TryAddSingleton(sp => new IpcClient(
            options,
            sp.GetRequiredService<ILogger<IpcClient>>()));

        services.TryAddSingleton<IAdminGateway, AdminGateway>();

        return services;
    }
}
