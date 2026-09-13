using MailServer.Application.Abstractions.Platform;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Platform;

/// <summary>Supplies the server's mail identity from validated configuration.</summary>
public sealed class ServerIdentityProvider : IServerIdentityProvider
{
    public ServerIdentityProvider(IOptions<MailServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        ServerOptions server = options.Value.Server;
        Hostname = server.Hostname;
        PublicIpAddress = server.PublicIpAddress;
        ProductName = server.ProductName;
    }

    public string Hostname { get; }

    public string? PublicIpAddress { get; }

    public string ProductName { get; }
}
