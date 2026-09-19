namespace MailServer.Domain.Imap;

/// <summary>
/// Writes a parsed message as RFC 3501 §9's <c>body</c>.
/// </summary>
/// <remarks>
/// <para>
/// §7.4.2 defines two items over one structure: <c>BODYSTRUCTURE</c> is "a parenthesized list
/// that describes the [MIME-IMB] body structure of a message", and <c>BODY</c> is its
/// "Non-extensible form". The difference is the extension data, which "is never returned with the
/// BODY fetch, but can be returned with a BODYSTRUCTURE fetch" — and §9 says the same twice more,
/// annotating both <c>body-ext-1part</c> and <c>body-ext-mpart</c> "MUST NOT be returned on
/// non-extensible 'BODY' fetch".
/// </para>
/// <para>
/// <b>Nothing beyond the extension data §7.4.2 defines is ever emitted.</b> "Server
/// implementations MUST NOT send such extension data until it has been defined by a revision of
/// this protocol." A client is required to accept it; that is not an invitation to invent some.
/// </para>
/// </remarks>
public static class ImapBodyStructure
{
    /// <summary>
    /// Writes one part, and everything nested inside it.
    /// </summary>
    /// <param name="part">The part to describe.</param>
    /// <param name="extended">Whether this is a <c>BODYSTRUCTURE</c> rather than a <c>BODY</c>.</param>
    /// <param name="builder">Where the pieces go.</param>
    public static void Format(ImapBodyPart part, bool extended, ImapSegmentBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(part);
        ArgumentNullException.ThrowIfNull(builder);

        builder.Append("(");

        if (part.IsMultipart)
        {
            FormatMultipart(part, extended, builder);
        }
        else
        {
            FormatSinglePart(part, extended, builder);
        }

        builder.Append(")");
    }

    /// <summary>
    /// §9: <c>body-type-mpart = 1*body SP media-subtype [SP body-ext-mpart]</c>.
    /// </summary>
    /// <remarks>
    /// §7.4.2: "Instead of a body type as the first element of the parenthesized list, there is a
    /// sequence of one or more nested body structures. The second element of the parenthesized
    /// list is the multipart subtype". Note what is <i>not</i> there: a multipart has no
    /// <c>body-fields</c>, so no parameters, no encoding and no octet count precede its subtype.
    /// The parameters reappear afterwards as the first of the extension fields.
    /// </remarks>
    private static void FormatMultipart(
        ImapBodyPart part,
        bool extended,
        ImapSegmentBuilder builder)
    {
        foreach (ImapBodyPart child in part.Children)
        {
            Format(child, extended, builder);
        }

        builder.Append(" ").AppendNString(part.Subtype);

        if (!extended)
        {
            return;
        }

        // §9: body-ext-mpart = body-fld-param [SP body-fld-dsp [SP body-fld-lang
        // [SP body-fld-loc *(SP body-extension)]]] - in that order, and only in that order.
        builder.Append(" ");
        FormatParameters(part.Parameters, builder);
        builder.Append(" ");
        FormatDisposition(part, builder);
        builder.Append(" ");
        FormatLanguages(part.Languages, builder);
        builder.Append(" ").AppendNString(part.Location);
    }

    /// <summary>
    /// §9: <c>body-type-1part = (body-type-basic / body-type-msg / body-type-text)
    /// [SP body-ext-1part]</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The three differ only in what follows <c>body-fields</c>. §7.4.2: "A body type of type
    /// MESSAGE and subtype RFC822 contains, immediately after the basic fields, the envelope
    /// structure, body structure, and size in text lines of the encapsulated message", and "A
    /// body type of type TEXT contains, immediately after the basic fields, the size of the body
    /// in text lines."
    /// </para>
    /// <para>
    /// <b>A <c>MESSAGE/RFC822</c> whose contents could not be taken apart is described as a basic
    /// part.</b> §9's <c>body-type-msg</c> requires an envelope and a nested body after the
    /// fields, and there is no <c>NIL</c> for either — so a part that has neither is one this
    /// production cannot describe, and <c>body-type-basic</c>'s only restriction is that a
    /// MESSAGE subtype "MUST NOT be 'RFC822'". That leaves the type and subtype as written and
    /// the structure grammatical, which is the closest to true that is available.
    /// </para>
    /// </remarks>
    private static void FormatSinglePart(
        ImapBodyPart part,
        bool extended,
        ImapSegmentBuilder builder)
    {
        bool message = part.Message is not null && part.Envelope is not null;

        builder.AppendNString(part.Type).Append(" ");
        builder.AppendNString(part.Subtype).Append(" ");

        // §9: body-fields = body-fld-param SP body-fld-id SP body-fld-desc SP body-fld-enc SP
        // body-fld-octets.
        FormatParameters(part.Parameters, builder);
        builder.Append(" ").AppendNString(part.Id);
        builder.Append(" ").AppendNString(part.Description);
        builder.Append(" ").AppendNString(part.Encoding);
        builder.Append(" ").Append(part.Content.Length);

        if (message)
        {
            builder.Append(" ");
            ImapEnvelopes.Format(part.Envelope!, builder);
            builder.Append(" ");
            Format(part.Message!, extended, builder);
            builder.Append(" ").Append(part.LineCount);
        }
        else if (part.Type.Equals("TEXT", StringComparison.Ordinal))
        {
            builder.Append(" ").Append(part.LineCount);
        }

        if (!extended)
        {
            return;
        }

        // §9: body-ext-1part = body-fld-md5 [SP body-fld-dsp [SP body-fld-lang
        // [SP body-fld-loc *(SP body-extension)]]].
        builder.Append(" ").AppendNString(part.Md5);
        builder.Append(" ");
        FormatDisposition(part, builder);
        builder.Append(" ");
        FormatLanguages(part.Languages, builder);
        builder.Append(" ").AppendNString(part.Location);
    }

    /// <summary>
    /// §9: <c>body-fld-param = "(" string SP string *(SP string SP string) ")" / nil</c>.
    /// </summary>
    /// <remarks>
    /// A flat list of alternating names and values, and <c>NIL</c> rather than <c>()</c> when
    /// there are none — the production has no empty-list form, and a client reading <c>()</c>
    /// would be reading a token the grammar does not contain. An odd trailing name is dropped for
    /// the same reason: a name without its value would end the list mid-pair.
    /// </remarks>
    private static void FormatParameters(IReadOnlyList<string> parameters, ImapSegmentBuilder builder)
    {
        int pairs = parameters.Count / 2;

        if (pairs == 0)
        {
            builder.Append("NIL");
            return;
        }

        builder.Append("(");

        for (int i = 0; i < pairs; i++)
        {
            if (i > 0)
            {
                builder.Append(" ");
            }

            builder.AppendNString(parameters[i * 2]).Append(" ");
            builder.AppendNString(parameters[(i * 2) + 1]);
        }

        builder.Append(")");
    }

    /// <summary>
    /// §9: <c>body-fld-dsp = "(" string SP body-fld-param ")" / nil</c>.
    /// </summary>
    private static void FormatDisposition(ImapBodyPart part, ImapSegmentBuilder builder)
    {
        if (part.DispositionType is not { } type)
        {
            builder.Append("NIL");
            return;
        }

        builder.Append("(").AppendNString(type).Append(" ");
        FormatParameters(part.DispositionParameters, builder);
        builder.Append(")");
    }

    /// <summary>
    /// §9: <c>body-fld-lang = nstring / "(" string *(SP string) ")"</c>.
    /// </summary>
    /// <remarks>
    /// Two shapes, and the count decides which: one tag is a bare string, and several are a
    /// parenthesised list. A single tag wrapped in parentheses is grammatical too, but the bare
    /// form is what the alternation exists for and what a client is likeliest to have been
    /// written against.
    /// </remarks>
    private static void FormatLanguages(IReadOnlyList<string> languages, ImapSegmentBuilder builder)
    {
        if (languages.Count == 0)
        {
            builder.Append("NIL");
            return;
        }

        if (languages.Count == 1)
        {
            builder.AppendNString(languages[0]);
            return;
        }

        builder.Append("(");

        for (int i = 0; i < languages.Count; i++)
        {
            if (i > 0)
            {
                builder.Append(" ");
            }

            builder.AppendNString(languages[i]);
        }

        builder.Append(")");
    }
}
