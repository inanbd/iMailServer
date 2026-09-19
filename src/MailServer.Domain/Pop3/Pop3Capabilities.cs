namespace MailServer.Domain.Pop3;

/// <summary>
/// The <c>CAPA</c> listing. RFC 2449.
/// </summary>
/// <remarks>
/// <para>
/// §5: "An +OK response is followed by a list of capabilities, one per line. Each capability name
/// MAY be followed by a single space and a space-separated list of parameters. […] The capability
/// list is terminated by a line containing a termination octet (".") and a CRLF pair."
/// </para>
/// <para>
/// <b>Everything listed is something this server will actually do in the state it is listed
/// in.</b> §5: "A capability description MUST document in which states the capability is
/// announced, and in which states the commands are valid. Capabilities available in the
/// AUTHORIZATION state MUST be announced in both states." The two lists here differ in exactly
/// the two entries whose answers change — <c>STLS</c>, which §4 of RFC 2595 permits only in
/// AUTHORIZATION, and <c>USER</c>, which is withheld until a password can be sent safely.
/// </para>
/// </remarks>
public static class Pop3Capabilities
{
    /// <summary>
    /// The capabilities offered in the AUTHORIZATION state.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b><c>USER</c> appears only once a password can be sent safely.</b> RFC 2449 §6.2: "The
    /// USER capability indicates that the USER and PASS commands are supported, although they may
    /// not be available to all users." Withholding it on a cleartext connection is the POP3
    /// counterpart of IMAP's <c>LOGINDISABLED</c>, which RFC 2595 §3.2 makes a MUST for a server
    /// implementing <c>STARTTLS</c>; that document gives POP3 no equivalent capability name, so
    /// the absence of this one is the only way to say it.
    /// </para>
    /// <para>
    /// <b><c>STLS</c> appears only where it is legal.</b> RFC 2595 §4: "The capability name
    /// "STLS" indicates this command is present and permitted in the current state", and the
    /// command is "Only permitted in AUTHORIZATION state". A server that listed it once TLS was
    /// active would be inviting a command it must then refuse.
    /// </para>
    /// <para>
    /// <b>There is no <c>APOP</c> entry and there never will be.</b> §6: "Note that there is no
    /// APOP capability, even though APOP is an optional command in [POP3]. Clients discover
    /// server support of APOP by the presence in the greeting banner of an initial challenge
    /// enclosed in angle brackets."
    /// </para>
    /// </remarks>
    /// <param name="product">The implementation name, for §6.9's <c>IMPLEMENTATION</c>.</param>
    /// <param name="tlsActive">Whether TLS is already active on this connection.</param>
    /// <param name="offerStartTls">Whether this listener can upgrade with <c>STLS</c>.</param>
    /// <param name="allowPlaintextLogin">Whether <c>USER</c> and <c>PASS</c> will be accepted.</param>
    public static IReadOnlyList<string> Authorization(
        string product,
        bool tlsActive,
        bool offerStartTls,
        bool allowPlaintextLogin)
    {
        ArgumentNullException.ThrowIfNull(product);

        List<string> capabilities = [];

        if (offerStartTls && !tlsActive)
        {
            capabilities.Add("STLS");
        }

        if (allowPlaintextLogin)
        {
            capabilities.Add("USER");
        }

        capabilities.AddRange(Common(product));

        return capabilities;
    }

    /// <summary>The capabilities offered in the TRANSACTION state.</summary>
    /// <remarks>
    /// <c>STLS</c> and <c>USER</c> are gone because neither command is legal here; §5's rule that
    /// "Capabilities available in the AUTHORIZATION state MUST be announced in both states" is
    /// about capabilities that remain available, and neither does.
    /// </remarks>
    public static IReadOnlyList<string> Transaction(string product)
    {
        ArgumentNullException.ThrowIfNull(product);

        return [.. Common(product)];
    }

    /// <summary>
    /// The entries that are true in both states.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>TOP</c> (§6.1) and <c>UIDL</c> (§6.8) name the two optional RFC 1939 commands this
    /// server implements. <c>RESP-CODES</c> (§6.4) commits it to the rule that "any response text
    /// issued by this server which begins with an open square bracket ("[") is an extended
    /// response code", which <see cref="Pop3Response.Format"/> guarantees by stripping brackets
    /// out of every text it did not put there itself.
    /// </para>
    /// <para>
    /// <c>PIPELINING</c> (§6.6) says the server "is capable of accepting multiple commands at a
    /// time" and "MUST process each command in turn". This server reads commands from a buffered
    /// reader one at a time and answers each before reading the next, which is exactly that; the
    /// one place it is not true is across an <c>STLS</c> upgrade, where the buffer is discarded —
    /// and RFC 2595 §4 forbids a client from pipelining there: "Once a client issues a STLS
    /// command, it MUST NOT issue further commands until a server response is seen and the TLS
    /// negotiation is complete."
    /// </para>
    /// <para>
    /// <c>IMPLEMENTATION</c> (§6.9) is "one or more tokens which identify the server", and §6.9
    /// notes it "may be convenient for the IMPLEMENTATION capability argument to not contain
    /// spaces, so that it is a single token" — so the product name is collapsed to one.
    /// </para>
    /// </remarks>
    private static IEnumerable<string> Common(string product)
    {
        yield return "TOP";
        yield return "UIDL";
        yield return "RESP-CODES";
        yield return "PIPELINING";

        if (Token(product) is { Length: > 0 } token)
        {
            yield return $"IMPLEMENTATION {token}";
        }
    }

    /// <summary>
    /// Reduces a product name to one printable token.
    /// </summary>
    /// <remarks>
    /// §3 makes a capability line's argument <c>1*VCHAR</c>, so a space would make the rest of
    /// the name a second argument and a control character would end the line. Neither is worth
    /// risking to render an operator's chosen name exactly.
    /// </remarks>
    private static string Token(string product)
    {
        System.Text.StringBuilder token = new(product.Length);

        foreach (char c in product)
        {
            if (c is >= '!' and <= '~')
            {
                token.Append(c);
            }
        }

        return token.ToString();
    }
}
