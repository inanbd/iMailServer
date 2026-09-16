using DnsClient;
using DnsClient.Protocol;
using MailServer.Application.Abstractions.Dkim;
using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace MailServer.Infrastructure.Dns;

/// <summary>
/// The one operation <see cref="DnsDkimPublicKeyResolver"/> actually needs from
/// <c>DnsClient.NET</c>.
/// </summary>
/// <remarks>
/// A separate interface from <see cref="IMxDnsClient"/>, even though both adapt the same
/// underlying <see cref="ILookupClient"/> singleton with an identical method shape: a fake for
/// DKIM verification tests should not need to pretend to be an MX resolver, and vice versa.
/// </remarks>
internal interface IDkimDnsClient
{
    Task<IDnsQueryResponse> QueryAsync(string query, QueryType queryType, CancellationToken cancellationToken);
}

/// <summary>Adapts a real <see cref="LookupClient"/> to <see cref="IDkimDnsClient"/>.</summary>
internal sealed class LookupClientDkimAdapter(ILookupClient client) : IDkimDnsClient
{
    public Task<IDnsQueryResponse> QueryAsync(string query, QueryType queryType, CancellationToken cancellationToken) =>
        ((IDnsQuery)client).QueryAsync(query, queryType, cancellationToken: cancellationToken);
}

/// <summary>
/// Fetches a DKIM selector's public key record from DNS. RFC 6376 §3.6.2.
/// </summary>
internal sealed class DnsDkimPublicKeyResolver(IDkimDnsClient client, ILogger<DnsDkimPublicKeyResolver> logger)
    : IDkimPublicKeyResolver
{
    public async Task<DkimPublicKeyLookupResult> ResolveAsync(
        DkimSelector selector,
        DomainName signingDomain,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(selector);
        ArgumentNullException.ThrowIfNull(signingDomain);

        string name = selector.ToDnsName(signingDomain);

        IDnsQueryResponse response;

        try
        {
            response = await client.QueryAsync(name, QueryType.TXT, cancellationToken).ConfigureAwait(false);
        }
        catch (DnsResponseException ex)
        {
            bool permanent = ex.Code == DnsResponseCode.NotExistentDomain;

            return permanent
                ? DkimPublicKeyLookupResult.Permanent($"{name} does not exist (NXDOMAIN).")
                : DkimPublicKeyLookupResult.Temporary($"TXT lookup for {name} failed: {ex.Message}");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "TXT lookup for {Name} failed at the transport level.", name);
            return DkimPublicKeyLookupResult.Temporary($"TXT lookup for {name} failed: {ex.Message}");
        }

        if (response.HasError)
        {
            bool permanent = response.Header.ResponseCode == DnsHeaderResponseCode.NotExistentDomain;

            return permanent
                ? DkimPublicKeyLookupResult.Permanent($"{name} does not exist (NXDOMAIN).")
                : DkimPublicKeyLookupResult.Temporary(
                    $"TXT lookup for {name} returned {response.Header.ResponseCode}: {response.ErrorMessage}");
        }

        List<TxtRecord> records = [.. response.Answers.OfType<TxtRecord>()];

        if (records.Count == 0)
        {
            return DkimPublicKeyLookupResult.Permanent($"{name} has no TXT record: no key published for this selector.");
        }

        if (records.Count > 1)
        {
            // RFC 6376 §3.6.2.2: more than one TXT resource record at this name is ambiguous
            // and MUST be treated as a failed lookup, never as "try the first one".
            return DkimPublicKeyLookupResult.Permanent(
                $"{name} has {records.Count} TXT records; exactly one is required to unambiguously " +
                "publish a DKIM key.");
        }

        // A TXT resource record can carry several character-strings; RFC 6376 requires
        // concatenating them in order before parsing the tag list.
        string recordText = string.Concat(records[0].Text);

        if (!DkimPublicKeyRecord.TryParse(recordText, out DkimPublicKeyRecord? record, out string? error))
        {
            return DkimPublicKeyLookupResult.Permanent($"{name}'s TXT record is not a valid DKIM key record: {error}");
        }

        return DkimPublicKeyLookupResult.Success(record);
    }
}
