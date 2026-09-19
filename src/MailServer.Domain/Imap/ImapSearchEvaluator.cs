using System.Globalization;
using System.Text;
using MailServer.Domain.Enums;

namespace MailServer.Domain.Imap;

/// <summary>
/// One message as a search sees it.
/// </summary>
/// <remarks>
/// The stored columns always, and the octets only when the criteria need them — see
/// <see cref="ImapSearchKey.NeedsContent"/>. A criteria of flags and dates never opens a message.
/// </remarks>
/// <param name="Summary">The stored facts: position, UID, flags, internal date, size.</param>
/// <param name="Content">The message's octets, or empty when they were not needed or not there.</param>
public sealed record ImapSearchCandidate(
    ImapMessageSummary Summary,
    ReadOnlyMemory<byte> Content);

/// <summary>Deciding whether a message matches RFC 3501 §6.4.4's criteria.</summary>
public static class ImapSearchEvaluator
{
    /// <summary>
    /// Whether one message matches.
    /// </summary>
    /// <param name="maxValue">
    /// What <c>*</c> resolves to for a bare sequence set: the folder's message count, or its
    /// largest UID for a <c>UID</c> key. Passed in because the tree cannot know the folder.
    /// </param>
    public static bool Matches(
        ImapSearchKey key,
        ImapSearchCandidate candidate,
        long maxValue,
        long maxUid)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(candidate);

        MessageFlags flags = candidate.Summary.Flags;

        return key.Kind switch
        {
            ImapSearchKind.All => true,

            ImapSearchKind.And => key.Children.All(c => Matches(c, candidate, maxValue, maxUid)),
            ImapSearchKind.Or => key.Children.Any(c => Matches(c, candidate, maxValue, maxUid)),
            ImapSearchKind.Not => !Matches(key.Children[0], candidate, maxValue, maxUid),

            ImapSearchKind.Answered => flags.HasFlag(MessageFlags.Answered),
            ImapSearchKind.Unanswered => !flags.HasFlag(MessageFlags.Answered),
            ImapSearchKind.Deleted => flags.HasFlag(MessageFlags.Deleted),
            ImapSearchKind.Undeleted => !flags.HasFlag(MessageFlags.Deleted),
            ImapSearchKind.Draft => flags.HasFlag(MessageFlags.Draft),
            ImapSearchKind.Undraft => !flags.HasFlag(MessageFlags.Draft),
            ImapSearchKind.Flagged => flags.HasFlag(MessageFlags.Flagged),
            ImapSearchKind.Unflagged => !flags.HasFlag(MessageFlags.Flagged),
            ImapSearchKind.Seen => flags.HasFlag(MessageFlags.Seen),
            ImapSearchKind.Unseen => !flags.HasFlag(MessageFlags.Seen),

            // \Recent is never set here, so these three have one answer each - and answering
            // them truthfully beats refusing perfectly ordinary criteria. §6.4.4 defines NEW as
            // "functionally equivalent to "(RECENT UNSEEN)"" and OLD as "NOT RECENT".
            ImapSearchKind.Recent => false,
            ImapSearchKind.New => false,
            ImapSearchKind.Old => true,

            // §6.4.4's KEYWORD is "Messages with the specified keyword flag set". This server
            // stores no keywords, so none is ever set - and its negation matches everything.
            ImapSearchKind.Keyword => false,
            ImapSearchKind.Unkeyword => true,

            ImapSearchKind.Larger => candidate.Summary.SizeBytes > key.Number,
            ImapSearchKind.Smaller => candidate.Summary.SizeBytes < key.Number,

            // "disregarding time and timezone" - §6.4.4 says so of every internal-date key, so
            // the comparison is on the date alone.
            ImapSearchKind.Before => DateOf(candidate.Summary.InternalDate) < key.Date,
            ImapSearchKind.On => DateOf(candidate.Summary.InternalDate) == key.Date,
            ImapSearchKind.Since => DateOf(candidate.Summary.InternalDate) >= key.Date,

            ImapSearchKind.SentBefore => SentDate(candidate) is { } sb && sb < key.Date,
            ImapSearchKind.SentOn => SentDate(candidate) is { } so && so == key.Date,
            ImapSearchKind.SentSince => SentDate(candidate) is { } ss && ss >= key.Date,

            ImapSearchKind.Uid => key.Set!.Contains(candidate.Summary.Uid, maxUid),
            ImapSearchKind.SequenceSet =>
                key.Set!.Contains(candidate.Summary.SequenceNumber, maxValue),

            ImapSearchKind.From => HeaderContains(candidate, "From", key.Text!),
            ImapSearchKind.To => HeaderContains(candidate, "To", key.Text!),
            ImapSearchKind.Cc => HeaderContains(candidate, "Cc", key.Text!),
            ImapSearchKind.Bcc => HeaderContains(candidate, "Bcc", key.Text!),
            ImapSearchKind.Subject => HeaderContains(candidate, "Subject", key.Text!),
            ImapSearchKind.Header => HeaderContains(candidate, key.Field!, key.Text!),

            ImapSearchKind.Body => Contains(BodyOf(candidate), key.Text!),
            ImapSearchKind.Text => Contains(Decode(candidate.Content), key.Text!),

            _ => false,
        };
    }

    private static DateOnly DateOf(DateTimeOffset instant) => DateOnly.FromDateTime(instant.Date);

    /// <summary>
    /// The date in the message's <c>Date:</c> header, if it has a readable one.
    /// </summary>
    /// <remarks>
    /// A message with no <c>Date:</c> header, or one that will not parse, matches no
    /// <c>SENT*</c> key. §6.4.4 defines them against "the [RFC-2822] Date: header", and a
    /// message without one has no such date — guessing the internal date instead would answer a
    /// question the client did not ask.
    /// </remarks>
    private static DateOnly? SentDate(ImapSearchCandidate candidate)
    {
        string value = HeaderValue(candidate, "Date");

        if (value.Length == 0)
        {
            return null;
        }

        // RFC 2822's date-time carries a zone; DateTimeOffset understands the common forms, and
        // "disregarding time and timezone" means only the date survives either way.
        return DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AllowWhiteSpaces,
            out DateTimeOffset parsed)
            ? DateOnly.FromDateTime(parsed.Date)
            : null;
    }

    /// <summary>
    /// Whether a named header's text contains a string.
    /// </summary>
    /// <remarks>
    /// §6.4.4: "Messages that have a header with the specified field-name […] and that contains
    /// the specified string in the text of the header (what comes after the colon)." So the name
    /// is matched and the value searched, not the whole line — a search for <c>HEADER FROM
    /// From</c> must not match every message by its own field name.
    /// </remarks>
    private static bool HeaderContains(ImapSearchCandidate candidate, string field, string text) =>
        text.Length == 0
            ? HeaderValue(candidate, field).Length > 0 || HasHeader(candidate, field)
            : Contains(HeaderValue(candidate, field), text);

    /// <summary>
    /// Every occurrence of a header's value, joined.
    /// </summary>
    /// <remarks>
    /// Joined rather than first-only, because <c>Received</c> and <c>Comments</c> legitimately
    /// repeat and a client searching them means any of them. Folded continuation lines are
    /// included, for the reason the body-section subsetting gives: a truncated value would match
    /// or fail on half a header.
    /// </remarks>
    private static string HeaderValue(ImapSearchCandidate candidate, string field)
    {
        StringBuilder found = new();

        foreach (string line in HeaderLines(candidate))
        {
            int colon = line.IndexOf(':', StringComparison.Ordinal);

            if (colon <= 0)
            {
                continue;
            }

            if (!line[..colon].Trim().Equals(field, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            found.Append(line[(colon + 1)..].Trim()).Append(' ');
        }

        return found.ToString();
    }

    private static bool HasHeader(ImapSearchCandidate candidate, string field)
    {
        foreach (string line in HeaderLines(candidate))
        {
            int colon = line.IndexOf(':', StringComparison.Ordinal);

            if (colon > 0 && line[..colon].Trim().Equals(field, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>The header block's logical lines, with folded continuations rejoined.</summary>
    private static IEnumerable<string> HeaderLines(ImapSearchCandidate candidate)
    {
        string header = Decode(HeaderOf(candidate));

        StringBuilder current = new();

        foreach (string raw in header.Split('\n'))
        {
            string line = raw.TrimEnd('\r');

            if (line.Length == 0)
            {
                break;
            }

            if (line[0] is ' ' or '\t')
            {
                current.Append(' ').Append(line.Trim());
                continue;
            }

            if (current.Length > 0)
            {
                yield return current.ToString();
            }

            current.Clear();
            current.Append(line);
        }

        if (current.Length > 0)
        {
            yield return current.ToString();
        }
    }

    private static ReadOnlyMemory<byte> HeaderOf(ImapSearchCandidate candidate) =>
        ImapBodySection.Extract(
            candidate.Content,
            HeaderSection) ?? ReadOnlyMemory<byte>.Empty;

    private static string BodyOf(ImapSearchCandidate candidate) =>
        Decode(ImapBodySection.Extract(
            candidate.Content,
            TextSection) ?? ReadOnlyMemory<byte>.Empty);

    /// <summary>
    /// Message octets as text for comparison.
    /// </summary>
    /// <remarks>
    /// UTF-8 with replacement rather than a strict decode: a message may be in any charset or
    /// none, and a search that threw on the first non-UTF-8 byte would fail on exactly the mail
    /// most worth finding. The replacement characters match nothing, which is the right outcome
    /// for bytes this server cannot interpret.
    /// </remarks>
    private static string Decode(ReadOnlyMemory<byte> octets) =>
        Encoding.UTF8.GetString(octets.Span);

    private static bool Contains(string haystack, string needle) =>
        needle.Length == 0 ||
        haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The two section specifiers a search needs, built once.
    /// </summary>
    /// <remarks>
    /// Peeking, though nothing here sets a flag: a search must never mark a message read, and
    /// building the specifier that way rather than relying on the caller is what makes that
    /// true wherever these are used.
    /// </remarks>
    private static readonly ImapSection HeaderSection =
        new(ImapSectionKind.Header, [], [], Peek: true, null, null);

    private static readonly ImapSection TextSection =
        new(ImapSectionKind.Text, [], [], Peek: true, null, null);
}
