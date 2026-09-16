using MailServer.Domain.Mail;

namespace MailServer.Infrastructure.Dkim;

/// <summary>
/// Reads just enough of a stored message from its start to locate and parse its header block,
/// shared by the outbound signer and the inbound verifier — both need the same bounded,
/// read-ahead-then-parse step before they can do anything else.
/// </summary>
internal static class MessageHeaderReader
{
    /// <summary>
    /// Reads from <paramref name="content"/>'s current position (normally the start of the
    /// message) until <see cref="RawMessageHeaders.TryParse"/> succeeds or
    /// <paramref name="maxHeaderBytes"/> is exhausted.
    /// </summary>
    /// <remarks>
    /// On success, <paramref name="content"/>'s position is left wherever the last read chunk
    /// happened to land — not at the header/body boundary. Callers that go on to read the body
    /// must <c>Seek</c> to <see cref="RawMessageHeaders.HeaderBlockLength"/> first;
    /// <paramref name="content"/> must therefore be seekable.
    /// </remarks>
    /// <returns>Null when no header/body boundary was found within the bound.</returns>
    public static async Task<RawMessageHeaders?> TryReadHeadersAsync(
        Stream content,
        int maxHeaderBytes,
        CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[maxHeaderBytes];
        int total = 0;

        while (total < buffer.Length)
        {
            int read = await content
                .ReadAsync(buffer.AsMemory(total, buffer.Length - total), cancellationToken)
                .ConfigureAwait(false);

            if (read == 0)
            {
                return null;
            }

            total += read;

            if (RawMessageHeaders.TryParse(buffer.AsMemory(0, total), out RawMessageHeaders? headers, out _))
            {
                return headers;
            }
        }

        return null;
    }
}
