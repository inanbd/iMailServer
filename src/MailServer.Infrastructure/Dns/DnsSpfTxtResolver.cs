using DnsClient;
using DnsClient.Protocol;
using MailServer.Application.Abstractions.Dns;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Dns;

/// <summary>The one operation <see cref="DnsSpfTxtResolver"/> actually needs from <c>DnsClient.NET</c>.</summary>
/// <remarks>
/// A separate interface from <see cref="IMxDnsClient"/> and <see cref="IDkimDnsClient"/>, even
/// though all three adapt the same underlying <see cref="ILookupClient"/> singleton with an
/// identical method shape — see <see cref="IDkimDnsClient"/>'s own remarks for why.
/// </remarks>
internal interface ISpfDnsClient
{
    Task<IDnsQueryResponse> QueryAsync(string query, QueryType queryType, CancellationToken cancellationToken);
}

/// <summary>Adapts a real <see cref="LookupClient"/> to <see cref="ISpfDnsClient"/>.</summary>
internal sealed class LookupClientSpfAdapter(ILookupClient client) : ISpfDnsClient
{
    public Task<IDnsQueryResponse> QueryAsync(string query, QueryType queryType, CancellationToken cancellationToken) =>
        ((IDnsQuery)client).QueryAsync(query, queryType, cancellationToken: cancellationToken);
}

/// <summary>Fetches every TXT record at a domain, for SPF record retrieval.</summary>
internal sealed class DnsSpfTxtResolver(ISpfDnsClient client, ILogger<DnsSpfTxtResolver> logger) : ISpfTxtResolver
{
    public async Task<SpfTxtLookupResult> GetTxtRecordsAsync(string domain, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        string name = domain;
        IDnsQueryResponse response;

        try
        {
            response = await client.QueryAsync(name, QueryType.TXT, cancellationToken).ConfigureAwait(false);
        }
        catch (DnsResponseException ex)
        {
            return ex.Code == DnsResponseCode.NotExistentDomain
                ? SpfTxtLookupResult.Permanent($"{name} does not exist (NXDOMAIN).")
                : SpfTxtLookupResult.Temporary($"TXT lookup for {name} failed: {ex.Message}");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "TXT lookup for {Name} failed at the transport level.", name);
            return SpfTxtLookupResult.Temporary($"TXT lookup for {name} failed: {ex.Message}");
        }

        if (response.HasError)
        {
            return response.Header.ResponseCode == DnsHeaderResponseCode.NotExistentDomain
                ? SpfTxtLookupResult.Permanent($"{name} does not exist (NXDOMAIN).")
                : SpfTxtLookupResult.Temporary(
                    $"TXT lookup for {name} returned {response.Header.ResponseCode}: {response.ErrorMessage}");
        }

        List<string> records = [.. response.Answers.OfType<TxtRecord>().Select(r => string.Concat(r.Text))];

        return SpfTxtLookupResult.Success(records);
    }
}
