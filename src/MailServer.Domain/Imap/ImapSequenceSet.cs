using System.Diagnostics.CodeAnalysis;

namespace MailServer.Domain.Imap;

/// <summary>
/// A parsed IMAP <c>sequence-set</c> — RFC 3501 §9's <c>seq-number</c>/<c>seq-range</c> grammar,
/// used by <c>FETCH</c>, <c>STORE</c>, <c>COPY</c>, <c>SEARCH</c> and their <c>UID</c> variants.
/// </summary>
/// <remarks>
/// <para>
/// <b>This type never materializes the numbers a range names.</b> <c>1:*</c> is two bytes on the
/// wire and a legal sequence-set against any mailbox, including one whose <c>UIDNEXT</c> has
/// climbed into the billions over years of delivery and expunging while holding only a handful
/// of messages today — UIDs are never reused, so a long-lived folder's highest UID has no
/// relationship to how many messages currently exist. Resolving <c>*</c> and normalising a range
/// (see <see cref="Resolve"/>) produces <i>bounds</i> for a caller to filter or query against,
/// never a list of every integer in between; building that list here would turn an ordinary
/// <c>UID FETCH 1:*</c> against such a mailbox into an attempt to allocate billions of entries.
/// </para>
/// <para>
/// <see cref="TryParse"/> caps the number of comma-separated segments accepted
/// (<see cref="MaxSegments"/>) for the same reason: the text itself, not just what it resolves
/// to, is attacker-controlled input from an unauthenticated-until-<c>LOGIN</c> connection.
/// </para>
/// </remarks>
public sealed class ImapSequenceSet
{
    /// <summary>
    /// The most comma-separated segments one sequence-set is parsed from. Generous for any real
    /// client's need (a client wanting "most of the mailbox" sends a range, not one segment per
    /// message) while bounding the work a single command line can force before it is even
    /// resolved against a mailbox.
    /// </summary>
    public const int MaxSegments = 10_000;

    private readonly IReadOnlyList<(SeqNumber Start, SeqNumber End)> _ranges;

    private ImapSequenceSet(IReadOnlyList<(SeqNumber Start, SeqNumber End)> ranges) => _ranges = ranges;

    /// <summary>One <c>seq-number</c>: a positive integer, or <c>*</c> — "the largest in use".</summary>
    private readonly record struct SeqNumber(long? Value)
    {
        public static readonly SeqNumber Wildcard = new((long?)null);

        public long Resolve(long maxValue) => Value ?? maxValue;
    }

    /// <summary>Parses a <c>sequence-set</c>.</summary>
    public static bool TryParse(string? text, [NotNullWhen(true)] out ImapSequenceSet? result)
    {
        result = null;

        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        string[] segments = text.Split(',');

        if (segments.Length == 0 || segments.Length > MaxSegments)
        {
            return false;
        }

        var ranges = new List<(SeqNumber Start, SeqNumber End)>(segments.Length);

        foreach (string segment in segments)
        {
            if (segment.Length == 0)
            {
                // ",," or a leading/trailing comma names an empty seq-number, which is not one.
                return false;
            }

            int colon = segment.IndexOf(':');

            if (colon < 0)
            {
                if (!TryParseSeqNumber(segment, out SeqNumber number))
                {
                    return false;
                }

                ranges.Add((number, number));
                continue;
            }

            if (!TryParseSeqNumber(segment[..colon], out SeqNumber start) ||
                !TryParseSeqNumber(segment[(colon + 1)..], out SeqNumber end))
            {
                return false;
            }

            ranges.Add((start, end));
        }

        result = new ImapSequenceSet(ranges);
        return true;
    }

    private static bool TryParseSeqNumber(string text, out SeqNumber result)
    {
        if (text == "*")
        {
            result = SeqNumber.Wildcard;
            return true;
        }

        // RFC 3501's nz-number: no leading zero, and (implicitly, since a sequence number or
        // UID of 0 names nothing - Delivery.Create refuses to allocate one) never zero itself.
        if (text.Length == 0 || text[0] == '0' || !long.TryParse(text, out long value) || value < 1)
        {
            result = default;
            return false;
        }

        result = new SeqNumber(value);
        return true;
    }

    /// <summary>
    /// Resolves every <c>*</c> against <paramref name="maxValue"/> and normalises each range so
    /// <c>Start &lt;= End</c> — RFC 3501 §9's own example notes <c>5:3</c> and <c>3:5</c> are
    /// equivalent, and a range written as <c>*:4</c> is exactly the same as <c>4:*</c>.
    /// </summary>
    /// <param name="maxValue">
    /// The highest sequence number or UID actually in use — what <c>*</c> means. Never look this
    /// up more than once per command: a UID and a message-sequence-number "largest in use" are
    /// different values, and this type is never told which one it was given.
    /// </param>
    /// <returns>
    /// Closed, inclusive <c>(Start, End)</c> bounds — for a caller to filter or query against,
    /// never to enumerate. See the class remarks.
    /// </returns>
    public IReadOnlyList<(long Start, long End)> Resolve(long maxValue)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxValue, 0);

        var resolved = new (long Start, long End)[_ranges.Count];

        for (int i = 0; i < _ranges.Count; i++)
        {
            long start = _ranges[i].Start.Resolve(maxValue);
            long end = _ranges[i].End.Resolve(maxValue);

            resolved[i] = start <= end ? (start, end) : (end, start);
        }

        return resolved;
    }

    /// <summary>Whether <paramref name="number"/> falls in any of this set's ranges.</summary>
    /// <remarks>
    /// For filtering one already-known value — a specific message sequence number, which is
    /// always bounded by how many messages actually exist — never for iterating a range's own
    /// span. See the class remarks.
    /// </remarks>
    public bool Contains(long number, long maxValue)
    {
        foreach ((long start, long end) in Resolve(maxValue))
        {
            if (number >= start && number <= end)
            {
                return true;
            }
        }

        return false;
    }
}
