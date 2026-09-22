using System.Globalization;
using System.Text;
using MailServer.Domain.Mail;

namespace MailServer.Domain.Filtering;

/// <summary>Envelope facts the header block cannot supply.</summary>
/// <param name="RecipientCount">How many recipients the envelope carried.</param>
/// <param name="ReceivedUtc">When this server accepted the message.</param>
public sealed record EnvelopeFacts(int RecipientCount, DateTimeOffset ReceivedUtc);

/// <summary>
/// Cheap structural checks over a message's header block.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every check here is about the shape of the message, never its subject matter.</b> This
/// product ships no word list and no trained model: it has no corpus to have built either
/// from, and one invented from intuition would encode its author's idea of what spam says —
/// which is how a filter ends up junking a hospital's mail because of what it is about.
/// <c>docs/Filtering.md</c> records this as a deliberate limit rather than an omission.
/// </para>
/// <para>
/// <b>The weights are small on purpose.</b> Not one of these is evidence on its own: plenty of
/// legitimate mail is sent by software that forgets a <c>Date</c>. They are worth something in
/// combination, and the thresholds are set so that two or three together are needed to move a
/// message — see <see cref="FilterPolicy"/>.
/// </para>
/// <para>
/// <b>Header values are read as ASCII and never decoded.</b> A signal must not carry content
/// (see <see cref="FilterSignal"/>), so nothing here needs the human-readable form of a
/// subject — only its shape. Not decoding also means no RFC 2047 decoder runs on a stranger's
/// bytes on the delivery path.
/// </para>
/// </remarks>
public static class HeaderHeuristics
{
    /// <summary>RFC 5322 §3.6 requires exactly one <c>Date</c>.</summary>
    public const double MissingDateScore = 1.0;

    /// <summary>RFC 5322 §3.6 requires exactly one <c>Message-ID</c> on a message this server receives.</summary>
    public const double MissingMessageIdScore = 1.0;

    /// <summary>
    /// More than one <c>From</c>, which RFC 5322 §3.6 forbids.
    /// </summary>
    /// <remarks>
    /// Heavy, because this is an attack rather than sloppiness. Clients differ on which one
    /// they display, and an authentication check that reads a different one than the client
    /// shows is a signature that passes for a sender the reader never sees.
    /// </remarks>
    public const double MultipleFromScore = 4.0;

    /// <summary>Neither <c>To</c> nor <c>Cc</c> names anybody.</summary>
    /// <remarks>
    /// The shape of a message blind-copied to a list. Legitimate senders do this too, which is
    /// why it is worth about as much as a missing <c>Date</c>.
    /// </remarks>
    public const double NoDestinationHeaderScore = 1.0;

    /// <summary>A <c>Date</c> far enough out to be a sorting trick.</summary>
    /// <remarks>
    /// A message dated next year sits at the top of a date-sorted inbox forever. The window is
    /// wide enough that an unsynchronised clock at the sending end does not trip it.
    /// </remarks>
    public const double ImplausibleDateScore = 2.0;

    /// <summary>A subject that is long and entirely upper-case.</summary>
    public const double ShoutingSubjectScore = 1.0;

    /// <summary>More envelope recipients than ordinary correspondence carries.</summary>
    public const double ManyRecipientsScore = 1.0;

    /// <summary>How far ahead of receipt a <c>Date</c> may be before it is implausible.</summary>
    public static TimeSpan MaxDateSkewAhead { get; } = TimeSpan.FromDays(2);

    /// <summary>How far behind receipt a <c>Date</c> may be before it is implausible.</summary>
    /// <remarks>
    /// Generous in this direction, because a message really can sit in a broken queue for days
    /// and arrive late through nobody's fault.
    /// </remarks>
    public static TimeSpan MaxDateSkewBehind { get; } = TimeSpan.FromDays(30);

    /// <summary>The shortest subject worth judging the case of.</summary>
    /// <remarks>
    /// "OK" and "FYI" are not shouting. Below this length a subject has too few letters for the
    /// observation to mean anything.
    /// </remarks>
    public const int MinShoutingSubjectLength = 12;

    /// <summary>Envelope recipients beyond which the count is itself a signal.</summary>
    public const int ManyRecipientsThreshold = 25;

    /// <summary>Runs every check.</summary>
    public static IReadOnlyList<FilterSignal> Evaluate(RawMessageHeaders headers, EnvelopeFacts envelope)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(envelope);

        List<FilterSignal> signals = [];

        int fromCount = headers.GetAll("From").Count();

        if (fromCount > 1)
        {
            signals.Add(FilterSignal.Create(
                "MULTIPLE_FROM",
                MultipleFromScore,
                $"The message has {fromCount} From headers; RFC 5322 allows one."));
        }

        if (!headers.GetAll("Date").Any())
        {
            signals.Add(FilterSignal.Create("MISSING_DATE", MissingDateScore, "The Date header is missing."));
        }
        else if (TryReadDate(headers, out DateTimeOffset sent))
        {
            TimeSpan skew = sent - envelope.ReceivedUtc;

            if (skew > MaxDateSkewAhead)
            {
                signals.Add(FilterSignal.Create(
                    "DATE_IN_FUTURE",
                    ImplausibleDateScore,
                    $"The Date header is {skew.TotalDays:0} days ahead of when the message arrived."));
            }
            else if (-skew > MaxDateSkewBehind)
            {
                signals.Add(FilterSignal.Create(
                    "DATE_IN_PAST",
                    ImplausibleDateScore,
                    $"The Date header is {-skew.TotalDays:0} days behind when the message arrived."));
            }
        }

        if (!headers.GetAll("Message-ID").Any())
        {
            signals.Add(FilterSignal.Create(
                "MISSING_MESSAGE_ID", MissingMessageIdScore, "The Message-ID header is missing."));
        }

        if (!headers.GetAll("To").Any() && !headers.GetAll("Cc").Any())
        {
            signals.Add(FilterSignal.Create(
                "NO_DESTINATION_HEADER",
                NoDestinationHeaderScore,
                "Neither a To nor a Cc header names a recipient."));
        }

        if (IsShouting(ValueOf(headers, "Subject")))
        {
            signals.Add(FilterSignal.Create(
                "SHOUTING_SUBJECT", ShoutingSubjectScore, "The subject is entirely upper-case."));
        }

        if (envelope.RecipientCount > ManyRecipientsThreshold)
        {
            signals.Add(FilterSignal.Create(
                "MANY_RECIPIENTS",
                ManyRecipientsScore,
                $"The envelope named {envelope.RecipientCount} recipients."));
        }

        return signals;
    }

    /// <summary>
    /// Whether a subject is long enough, and cased uniformly enough, to count as shouting.
    /// </summary>
    /// <remarks>
    /// <b>Only cased letters are examined, and a subject with none is not shouting.</b> Most of
    /// the world's scripts have no case at all, and a check that treated "no lower-case letters"
    /// as the test would fire on every message written in Chinese, Arabic, Hebrew, Japanese or
    /// Korean — a filter that scored mail for the alphabet it was written in.
    /// </remarks>
    public static bool IsShouting(string? subject)
    {
        if (subject is null)
        {
            return false;
        }

        // An encoded-word subject is a base64 or quoted-printable blob whose case says nothing
        // about the text. Decoding it here would put a decoder on the delivery path for a
        // one-point heuristic; skipping it costs only that this check does not apply.
        if (subject.Contains("=?", StringComparison.Ordinal))
        {
            return false;
        }

        int upper = 0;
        int lower = 0;

        foreach (char c in subject)
        {
            switch (CharUnicodeInfo.GetUnicodeCategory(c))
            {
                case UnicodeCategory.UppercaseLetter:
                    upper++;
                    break;
                case UnicodeCategory.LowercaseLetter or UnicodeCategory.TitlecaseLetter:
                    lower++;
                    break;
                default:
                    break;
            }
        }

        return lower == 0 && upper >= MinShoutingSubjectLength;
    }

    private static bool TryReadDate(RawMessageHeaders headers, out DateTimeOffset value)
    {
        string? raw = ValueOf(headers, "Date");

        if (raw is null)
        {
            value = default;
            return false;
        }

        // A malformed Date is not scored. RFC 5322 §3.3's grammar has obsolete forms real
        // senders still emit, and a parser that treated everything it could not read as
        // suspicious would be scoring its own coverage gaps.
        return DateTimeOffset.TryParse(
            raw.Trim(), CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out value);
    }

    /// <summary>
    /// The first value for a header name, as ASCII.
    /// </summary>
    /// <remarks>
    /// The same four lines <c>ArcChain</c> keeps privately, and kept privately here for the same
    /// reason: <c>RawMessageHeaders</c> hands out wire bytes deliberately, because DKIM needs
    /// them unaltered, and a shared convenience that returned a decoded string would be the one
    /// every future caller reached for.
    /// </remarks>
    private static string? ValueOf(RawMessageHeaders headers, string name)
    {
        foreach (RawHeaderField field in headers.GetAll(name))
        {
            ReadOnlySpan<byte> raw = field.RawBytes.Span;
            int colon = raw.IndexOf((byte)':');

            if (colon < 0)
            {
                return null;
            }

            ReadOnlySpan<byte> value = raw[(colon + 1)..];

            // GetAll hands back the field including its terminating CRLF; a folded field carries
            // interior ones too. Unfolding to spaces keeps a folded subject on one line.
            return Encoding.ASCII.GetString(value).Replace('\r', ' ').Replace('\n', ' ').Trim();
        }

        return null;
    }
}
