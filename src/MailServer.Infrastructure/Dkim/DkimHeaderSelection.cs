using System.Text;
using MailServer.Domain.Mail;

namespace MailServer.Infrastructure.Dkim;

/// <summary>
/// Implements RFC 6376 §5.4.2's header-selection algorithm: shared by the signer and the
/// verifier because both must reconstruct <i>exactly</i> the same canonical byte sequence for a
/// given <c>h=</c> list against a given message's headers, or verification would fail for
/// reasons that have nothing to do with whether the signature is genuine.
/// </summary>
internal static class DkimHeaderSelection
{
    /// <summary>
    /// Appends the relaxed-canonical form of each name in <paramref name="namesToSign"/>,
    /// consuming real header fields from the bottom of the message upward for repeats, and
    /// treating any name requested more times than it actually occurs as present with an empty
    /// value — the mechanism that makes oversigning (listing a name more times than it currently
    /// appears) work as a defence against a header added later.
    /// </summary>
    public static void AppendSelectedHeaders(
        List<byte> result,
        RawMessageHeaders headers,
        IReadOnlyList<string> namesToSign)
    {
        var remainingByName = new Dictionary<string, List<RawHeaderField>>(StringComparer.OrdinalIgnoreCase);

        foreach (RawHeaderField field in headers.Fields)
        {
            if (!remainingByName.TryGetValue(field.Name, out List<RawHeaderField>? list))
            {
                list = [];
                remainingByName[field.Name] = list;
            }

            list.Add(field);
        }

        foreach (string name in namesToSign)
        {
            if (remainingByName.TryGetValue(name, out List<RawHeaderField>? candidates) && candidates.Count > 0)
            {
                RawHeaderField field = candidates[^1];
                candidates.RemoveAt(candidates.Count - 1);
                result.AddRange(DkimHeaderCanonicalizer.Canonicalize(field));
            }
            else
            {
                // Phantom: relaxed-canonical form of a header with this name and an empty value.
                result.AddRange(Encoding.ASCII.GetBytes(name.ToLowerInvariant() + ":\r\n"));
            }
        }
    }
}
