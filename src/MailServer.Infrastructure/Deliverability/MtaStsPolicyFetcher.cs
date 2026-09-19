using System.Globalization;
using System.Net;
using System.Security.Authentication;
using MailServer.Application.Abstractions.Deliverability;
using MailServer.Domain.Deliverability;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Deliverability;

/// <summary>
/// Reads an MTA-STS policy over HTTPS, distinguishing every way the read can fail.
/// </summary>
/// <remarks>
/// <para>
/// Owns one <see cref="HttpClient"/> rather than taking a factory, since this project references
/// no HTTP extensions package and needs exactly one client with one configuration.
/// <see cref="SocketsHttpHandler.PooledConnectionLifetime"/> is what an
/// <c>IHttpClientFactory</c> would otherwise be providing: without it a pooled connection
/// outlives a DNS change, and a diagnostic tool that kept talking to the host an operator has
/// just moved away from would be worse than useless.
/// </para>
/// <para>
/// <b>Redirects are not followed.</b> RFC 8461 §3.2 fixes the URL, and the common case for a
/// redirect here is a web server sending every unknown path to a landing page — which would
/// otherwise be fetched, fail to parse, and be reported as a malformed policy rather than as
/// the missing one it is.
/// </para>
/// </remarks>
public sealed class MtaStsPolicyFetcher : IMtaStsPolicyFetcher, IDisposable
{
    /// <summary>
    /// The most of a policy resource that is read.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §3.2's policy is a handful of short lines, and this request goes to a host named
    /// by the domain under test. Without a cap, a host that streams indefinitely would hold this
    /// report open for as long as it liked.
    /// </remarks>
    public const int MaxPolicyBytes = 64 * 1024;

    /// <summary>How long the whole fetch may take.</summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private readonly HttpClient _client;
    private bool _disposed;

    public MtaStsPolicyFetcher()
    {
        _client = new HttpClient(
            new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                PooledConnectionLifetime = TimeSpan.FromMinutes(2),
                AutomaticDecompression = DecompressionMethods.None,
            },
            disposeHandler: true)
        {
            Timeout = Timeout,
            MaxResponseContentBufferSize = MaxPolicyBytes,
        };
    }

    /// <summary>The URL a policy is served from. RFC 8461 §3.2.</summary>
    public static string UrlFor(DomainName domain)
    {
        ArgumentNullException.ThrowIfNull(domain);

        return $"https://mta-sts.{domain.Value}/.well-known/mta-sts.txt";
    }

    /// <inheritdoc />
    public async Task<MtaStsPolicyFetch> FetchAsync(
        DomainName domain,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domain);

        string url = UrlFor(domain);

        try
        {
            using HttpResponseMessage response = await _client
                .GetAsync(new Uri(url), HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return new MtaStsPolicyFetch(
                    MtaStsFetchOutcome.NotFound,
                    null,
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"{url} answered {(int)response.StatusCode} {response.ReasonPhrase}."));
            }

            // §3.2: "senders SHOULD validate that the media type is 'text/plain' to guard
            // against cases where web servers allow untrusted users to host non-text content
            // (typically, HTML or images) at a user-defined path." The charset parameter is
            // explicitly not part of that comparison.
            string? mediaType = response.Content.Headers.ContentType?.MediaType;

            if (!string.Equals(mediaType, "text/plain", StringComparison.OrdinalIgnoreCase))
            {
                return new MtaStsPolicyFetch(
                    MtaStsFetchOutcome.WrongMediaType,
                    null,
                    $"{url} was served as {mediaType ?? "no media type"} rather than text/plain.");
            }

            string text = await response.Content
                .ReadAsStringAsync(cancellationToken)
                .ConfigureAwait(false);

            return new MtaStsPolicyFetch(MtaStsFetchOutcome.Fetched, text, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // A TLS failure is its own outcome, and it hides two levels down: HttpClient wraps
            // the handler's exception, which wraps the authentication failure. Reporting it as
            // "unreachable" would send an operator to check a firewall when the host answered
            // perfectly and only its certificate was wrong.
            return IsTlsFailure(ex)
                ? new MtaStsPolicyFetch(
                    MtaStsFetchOutcome.TlsFailed,
                    null,
                    $"The TLS handshake with mta-sts.{domain.Value} failed: {Innermost(ex).Message}")
                : new MtaStsPolicyFetch(
                    MtaStsFetchOutcome.Unreachable,
                    null,
                    $"{url} could not be reached: {Innermost(ex).Message}");
        }
    }

    private static bool IsTlsFailure(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is AuthenticationException)
            {
                return true;
            }
        }

        return false;
    }

    private static Exception Innermost(Exception exception)
    {
        Exception current = exception;

        while (current.InnerException is { } inner)
        {
            current = inner;
        }

        return current;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _client.Dispose();
    }
}
