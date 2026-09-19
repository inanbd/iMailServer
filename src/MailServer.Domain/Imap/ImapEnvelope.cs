namespace MailServer.Domain.Imap;

/// <summary>
/// RFC 3501 §7.4.2's envelope structure: a message's header, parsed.
/// </summary>
/// <remarks>
/// <para>
/// §6.4.5: "The envelope structure of the message. This is computed by the server by parsing the
/// [RFC-2822] header into the component parts, defaulting various fields as necessary." It is
/// what a client draws a message list from — the sender, the subject and the date of every
/// message in a folder, without fetching one byte of any of them.
/// </para>
/// <para>
/// <b>The fields are the header's text, not a normalised form of it.</b> §7.4.2's example gives
/// the date as <c>"Wed, 17 Jul 1996 02:23:25 -0700 (PDT)"</c> — the header line as written,
/// comment and all. Reformatting it would be a second opinion about a value the client is
/// perfectly able to parse, and would lose the timezone name that the sender chose to include.
/// </para>
/// <para>
/// <b>Absent and empty are different answers.</b> §7.4.2: "If the Date, Subject, In-Reply-To,
/// and Message-ID header lines are absent in the [RFC-2822] header, the corresponding member of
/// the envelope is NIL; if these header lines are present but empty the corresponding member of
/// the envelope is the empty string." So null here means the header was not there at all.
/// </para>
/// </remarks>
/// <param name="Date">The <c>Date</c> header verbatim, or null when absent.</param>
/// <param name="Subject">The <c>Subject</c> header verbatim, or null when absent.</param>
/// <param name="From">The <c>From</c> addresses, or null when there are none.</param>
/// <param name="Sender">The <c>Sender</c> addresses, defaulted to <paramref name="From"/>.</param>
/// <param name="ReplyTo">The <c>Reply-To</c> addresses, defaulted to <paramref name="From"/>.</param>
/// <param name="To">The <c>To</c> addresses, or null when there are none.</param>
/// <param name="Cc">The <c>Cc</c> addresses, or null when there are none.</param>
/// <param name="Bcc">The <c>Bcc</c> addresses, or null when there are none.</param>
/// <param name="InReplyTo">The <c>In-Reply-To</c> header verbatim, or null when absent.</param>
/// <param name="MessageId">The <c>Message-ID</c> header verbatim, or null when absent.</param>
public sealed record ImapEnvelope(
    string? Date,
    string? Subject,
    IReadOnlyList<ImapAddress>? From,
    IReadOnlyList<ImapAddress>? Sender,
    IReadOnlyList<ImapAddress>? ReplyTo,
    IReadOnlyList<ImapAddress>? To,
    IReadOnlyList<ImapAddress>? Cc,
    IReadOnlyList<ImapAddress>? Bcc,
    string? InReplyTo,
    string? MessageId);

/// <summary>Reading an envelope out of a message, and writing one onto the wire.</summary>
public static class ImapEnvelopes
{
    /// <summary>
    /// The envelope of a message whose octets could not be read.
    /// </summary>
    /// <remarks>
    /// Every member NIL, because §9's <c>msg-att-static</c> is <c>"ENVELOPE" SP envelope</c> and
    /// offers no NIL for the structure as a whole — unlike a body section, which has one. A
    /// folder holding one message whose file has gone missing still has to open, so the item is
    /// answered with the empty structure rather than failing the command.
    /// </remarks>
    public static ImapEnvelope Missing { get; } =
        new(null, null, null, null, null, null, null, null, null, null);

    /// <summary>
    /// Parses a stored message's header into an envelope.
    /// </summary>
    /// <remarks>
    /// The whole message may be passed: <see cref="ImapHeaderFields.Read"/> stops at the blank
    /// line that RFC 2822 §2.1 puts between the header and the body, so the body is never
    /// scanned and a message that is all header parses just the same.
    /// </remarks>
    public static ImapEnvelope Read(ReadOnlyMemory<byte> message) =>
        From(ImapHeaderFields.Read(message));

    /// <summary>
    /// Builds an envelope from header fields that have already been read.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Sender and Reply-To default to From, and that is a MUST on the server.</b> §7.4.2: "If
    /// the Sender or Reply-To lines are absent in the [RFC-2822] header, or are present but
    /// empty, the server sets the corresponding member of the envelope to be the same value as
    /// the from member (the client is not expected to know to do this)." A client that receives
    /// NIL there will show no reply address at all.
    /// </para>
    /// <para>
    /// <b>The four string members keep the present-but-empty case and the six address members
    /// lose it.</b> That asymmetry is §7.4.2's, not a shortcut: the address members are "absent
    /// […] or are present but empty" together, because §9's <c>env-from</c> is
    /// <c>"(" 1*address ")" / nil</c> and has no empty-list form to put an empty header in.
    /// </para>
    /// </remarks>
    public static ImapEnvelope From(IReadOnlyList<ImapHeaderField> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);

        IReadOnlyList<ImapAddress>? from = Addresses(fields, "From");

        return new ImapEnvelope(
            ImapHeaderFields.First(fields, "Date"),
            ImapHeaderFields.First(fields, "Subject"),
            from,
            Addresses(fields, "Sender") ?? from,
            Addresses(fields, "Reply-To") ?? from,
            Addresses(fields, "To"),
            Addresses(fields, "Cc"),
            Addresses(fields, "Bcc"),
            ImapHeaderFields.First(fields, "In-Reply-To"),
            ImapHeaderFields.First(fields, "Message-ID"));
    }

    /// <summary>
    /// Writes an envelope in §9's <c>envelope</c> form.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §9: <c>envelope = "(" env-date SP env-subject SP env-from SP env-sender SP env-reply-to SP
    /// env-to SP env-cc SP env-bcc SP env-in-reply-to SP env-message-id ")"</c>. Ten members,
    /// always ten, in that order — a client reads them positionally and a missing one shifts
    /// every member after it.
    /// </para>
    /// <para>
    /// <b>No space between address structures.</b> §9's <c>env-from = "(" 1*address ")"</c> is a
    /// bare repetition with no separator, so a two-address list is <c>((…)(…))</c>. The spacing
    /// in §7.4.2's worked example is the document's line wrapping rather than the wire form.
    /// </para>
    /// </remarks>
    public static void Format(ImapEnvelope envelope, ImapSegmentBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(builder);

        builder.Append("(").AppendNString(envelope.Date).Append(" ");
        builder.AppendNString(envelope.Subject).Append(" ");

        FormatAddresses(envelope.From, builder);
        builder.Append(" ");
        FormatAddresses(envelope.Sender, builder);
        builder.Append(" ");
        FormatAddresses(envelope.ReplyTo, builder);
        builder.Append(" ");
        FormatAddresses(envelope.To, builder);
        builder.Append(" ");
        FormatAddresses(envelope.Cc, builder);
        builder.Append(" ");
        FormatAddresses(envelope.Bcc, builder);

        builder.Append(" ").AppendNString(envelope.InReplyTo).Append(" ");
        builder.AppendNString(envelope.MessageId).Append(")");
    }

    private static void FormatAddresses(
        IReadOnlyList<ImapAddress>? addresses,
        ImapSegmentBuilder builder)
    {
        if (addresses is null || addresses.Count == 0)
        {
            builder.Append("NIL");
            return;
        }

        builder.Append("(");

        foreach (ImapAddress address in addresses)
        {
            builder.Append("(").AppendNString(address.Name).Append(" ");
            builder.AppendNString(address.Route).Append(" ");
            builder.AppendNString(address.Mailbox).Append(" ");
            builder.AppendNString(address.Host).Append(")");
        }

        builder.Append(")");
    }

    /// <summary>The addresses of one field, or null when the field is absent or blank.</summary>
    private static IReadOnlyList<ImapAddress>? Addresses(
        IReadOnlyList<ImapHeaderField> fields,
        string name)
    {
        if (ImapHeaderFields.First(fields, name) is not { } value || value.Length == 0)
        {
            return null;
        }

        IReadOnlyList<ImapAddress> parsed = ImapAddressList.Parse(value);

        return parsed.Count == 0 ? null : parsed;
    }
}
