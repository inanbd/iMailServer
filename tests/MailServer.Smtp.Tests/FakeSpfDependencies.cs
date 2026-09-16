using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.ValueObjects;

namespace MailServer.Smtp.Tests;

/// <summary>
/// Reports no SPF record for any domain, so <c>SmtpConnectionHandler</c>'s SPF evaluation is a
/// transparent no-op (<c>SpfResult.None</c>) for suites whose subject is the wire protocol, not
/// SPF itself — SPF's own behaviour is covered by <c>MailServer.Authentication.Tests</c>.
/// </summary>
internal sealed class NoOpTxtRecordResolver : ITxtRecordResolver
{
    public Task<TxtLookupResult> GetTxtRecordsAsync(string domain, CancellationToken cancellationToken) =>
        Task.FromResult(TxtLookupResult.Success([]));
}

/// <summary>Never resolves anything, for the same reason as <see cref="NoOpTxtRecordResolver"/>.</summary>
internal sealed class NoOpDnsResolver : IDnsResolver
{
    public Task<MxLookupResult> ResolveMxAsync(DomainName domain, CancellationToken cancellationToken) =>
        Task.FromResult(MxLookupResult.Permanent("not used in this test"));

    public Task<AddressLookupResult> ResolveAddressesAsync(string hostname, CancellationToken cancellationToken) =>
        Task.FromResult(AddressLookupResult.Permanent("not used in this test"));
}
