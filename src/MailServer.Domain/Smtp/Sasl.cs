using System.Buffers;
using System.Text;

namespace MailServer.Domain.Smtp;

/// <summary>Where a SASL exchange has got to.</summary>
public enum SaslOutcome
{
    /// <summary>The server needs another line from the client.</summary>
    Challenge = 0,

    /// <summary>The client supplied a complete credential. It has not been verified yet.</summary>
    Completed = 1,

    /// <summary>The exchange is malformed and cannot continue.</summary>
    Failed = 2,

    /// <summary>The client sent <c>*</c> to abandon the exchange, which RFC 4954 §4 permits.</summary>
    Cancelled = 3,
}

/// <summary>
/// A username and password supplied by a client, held only as long as it takes to verify them.
/// </summary>
/// <remarks>
/// <para>
/// The password lives in a <see cref="char"/> array rather than a string so it can be
/// overwritten. A string cannot: it is immutable, it sits on the managed heap until a collection
/// that may never come, and it can be copied by compaction on the way. That is not a complete
/// defence — a process dump taken at the wrong moment still contains it — but the window is the
/// difference between "present during verification" and "present for the life of the process".
/// </para>
/// <para>
/// <b>Dispose it.</b> The finaliser is deliberately absent: a credential that depended on one
/// would be cleared at an unpredictable time, which is the same as not being cleared.
/// </para>
/// </remarks>
public sealed class SaslCredential : IDisposable
{
    private char[]? _password;

    /// <summary>Creates a credential, taking ownership of the password buffer.</summary>
    public SaslCredential(string authenticationIdentity, string authorizationIdentity, char[] password)
    {
        ArgumentNullException.ThrowIfNull(authenticationIdentity);
        ArgumentNullException.ThrowIfNull(authorizationIdentity);
        ArgumentNullException.ThrowIfNull(password);

        AuthenticationIdentity = authenticationIdentity;
        AuthorizationIdentity = authorizationIdentity;
        _password = password;
    }

    /// <summary>Who is proving their identity — the mailbox address.</summary>
    public string AuthenticationIdentity { get; }

    /// <summary>
    /// Who they are asking to act as.
    /// </summary>
    /// <remarks>
    /// Usually empty, meaning "myself". PLAIN carries it as a separate field, and a server that
    /// ignored it would let a client authenticate as one mailbox and be treated as another.
    /// </remarks>
    public string AuthorizationIdentity { get; }

    /// <summary>The password. Valid until <see cref="Dispose"/>.</summary>
    public ReadOnlySpan<char> Password =>
        _password ?? throw new ObjectDisposedException(nameof(SaslCredential));

    /// <summary>Overwrites the password buffer.</summary>
    public void Dispose()
    {
        if (_password is null)
        {
            return;
        }

        Array.Clear(_password);
        _password = null;
    }
}

/// <summary>One step of a SASL exchange.</summary>
/// <param name="Outcome">What the server should do next.</param>
/// <param name="Challenge">
/// The base64 challenge to send with the 334, when <paramref name="Outcome"/> is
/// <see cref="SaslOutcome.Challenge"/>. Empty string means an empty challenge, which is legal.
/// </param>
/// <param name="Credential">The credential, when the exchange completed. The caller disposes it.</param>
/// <param name="Diagnostic">Why it failed. Safe to log — it never contains credential material.</param>
public sealed record SaslStep(
    SaslOutcome Outcome,
    string? Challenge = null,
    SaslCredential? Credential = null,
    string? Diagnostic = null)
{
    public static SaslStep Challenging(string challenge) => new(SaslOutcome.Challenge, challenge);

    public static SaslStep Complete(SaslCredential credential) =>
        new(SaslOutcome.Completed, Credential: credential);

    public static SaslStep Failure(string diagnostic) => new(SaslOutcome.Failed, Diagnostic: diagnostic);

    public static SaslStep Cancelled() => new(SaslOutcome.Cancelled, Diagnostic: "The client cancelled the exchange.");
}

/// <summary>
/// One SASL mechanism, as a state machine with no I/O.
/// </summary>
/// <remarks>
/// Mechanisms are stateful — PLAIN takes one line, LOGIN takes three — so an instance belongs to
/// one exchange on one session and is discarded afterwards.
/// </remarks>
public interface ISaslMechanism : IDisposable
{
    /// <summary>The name as it appears after <c>AUTH</c>, upper case.</summary>
    string Name { get; }

    /// <summary>Begins the exchange.</summary>
    /// <param name="initialResponse">
    /// The base64 argument on the AUTH line, if the client sent one. RFC 4954 §4 allows it, and
    /// most clients use it to save a round trip. Null means it was absent, which is different
    /// from present-and-empty (<c>=</c>).
    /// </param>
    SaslStep Start(string? initialResponse);

    /// <summary>Supplies the client's answer to the previous challenge.</summary>
    SaslStep Advance(string response);
}

/// <summary>Shared base64 handling for the mechanisms.</summary>
/// <remarks>
/// Bounded and total. Every line here came off the network, so a malformed one is an ordinary
/// event that must produce a failure rather than an exception.
/// </remarks>
public static class SaslEncoding
{
    /// <summary>
    /// Longest base64 response accepted.
    /// </summary>
    /// <remarks>
    /// A SASL response carrying a username and password has no business being large. The SMTP
    /// line limit already bounds it, and this bounds it again far lower — a mechanism is not the
    /// place to discover that someone has sent four kilobytes of base64.
    /// </remarks>
    public const int MaxResponseChars = 1024;

    /// <summary>The single character a client sends to abandon an exchange (RFC 4954 §4).</summary>
    public const string CancellationToken = "*";

    /// <summary>Decodes a base64 response into a byte buffer the caller must clear.</summary>
    /// <returns>False when the response is not valid base64 or is too long.</returns>
    public static bool TryDecode(string? response, out byte[] decoded)
    {
        decoded = [];

        if (response is null || response.Length > MaxResponseChars)
        {
            return false;
        }

        // An empty response decodes to zero bytes, which several mechanisms treat as meaningful.
        if (response.Length == 0)
        {
            return true;
        }

        byte[] buffer = new byte[((response.Length * 3) / 4) + 3];

        if (!Convert.TryFromBase64String(response, buffer, out int written))
        {
            Array.Clear(buffer);
            return false;
        }

        decoded = buffer[..written];

        // The oversized scratch buffer held the same secret; clearing the copy is not enough.
        Array.Clear(buffer);

        return true;
    }

    /// <summary>Encodes a challenge for the 334 reply.</summary>
    public static string Encode(string text) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    /// <summary>
    /// Converts decoded bytes to characters in a buffer the caller owns and must clear.
    /// </summary>
    /// <remarks>
    /// Via <see cref="ArrayPool{T}"/> rather than <c>Encoding.UTF8.GetString</c>, because a
    /// string of the password is exactly what <see cref="SaslCredential"/> exists to avoid.
    /// </remarks>
    public static char[] ToClearableChars(ReadOnlySpan<byte> utf8)
    {
        int count = Encoding.UTF8.GetCharCount(utf8);
        char[] chars = new char[count];

        Encoding.UTF8.GetChars(utf8, chars);

        return chars;
    }
}

/// <summary>
/// SASL PLAIN (RFC 4616).
/// </summary>
/// <remarks>
/// <para>
/// One message: <c>authzid NUL authcid NUL password</c>, base64-encoded. The client may send it
/// on the AUTH line itself, which is why <see cref="Start"/> takes an initial response.
/// </para>
/// <para>
/// <b>It sends the password in a form equivalent to the clear</b>, which is acceptable only
/// inside TLS. That condition is enforced where the mechanism is offered and again where it is
/// selected — see <c>SmtpCapabilities.MayOfferAuthentication</c>.
/// </para>
/// </remarks>
public sealed class SaslPlainMechanism : ISaslMechanism
{
    private bool _awaitingResponse;

    /// <inheritdoc />
    public string Name => "PLAIN";

    /// <inheritdoc />
    public SaslStep Start(string? initialResponse)
    {
        if (initialResponse is null)
        {
            // No initial response, so ask for one. RFC 4954 §4: the challenge is empty.
            _awaitingResponse = true;

            return SaslStep.Challenging(string.Empty);
        }

        return Decode(initialResponse);
    }

    /// <inheritdoc />
    public SaslStep Advance(string response)
    {
        if (!_awaitingResponse)
        {
            return SaslStep.Failure("PLAIN received a response it did not ask for.");
        }

        _awaitingResponse = false;

        return Decode(response);
    }

    private static SaslStep Decode(string response)
    {
        if (response == SaslEncoding.CancellationToken)
        {
            return SaslStep.Cancelled();
        }

        // RFC 4954 §4: "=" means an empty initial response, as distinct from an absent one.
        string payload = response == "=" ? string.Empty : response;

        if (!SaslEncoding.TryDecode(payload, out byte[] decoded))
        {
            return SaslStep.Failure("The PLAIN response is not valid base64.");
        }

        try
        {
            // Split on NUL. Exactly two separators, so a password containing a NUL - which
            // cannot happen through this encoding - does not silently shift the fields.
            int first = Array.IndexOf(decoded, (byte)0);

            if (first < 0)
            {
                return SaslStep.Failure("The PLAIN response is missing its field separators.");
            }

            int second = Array.IndexOf(decoded, (byte)0, first + 1);

            if (second < 0)
            {
                return SaslStep.Failure("The PLAIN response is missing its second field separator.");
            }

            string authorizationIdentity = Encoding.UTF8.GetString(decoded.AsSpan(0, first));
            string authenticationIdentity = Encoding.UTF8.GetString(decoded.AsSpan(first + 1, second - first - 1));

            if (authenticationIdentity.Length == 0)
            {
                return SaslStep.Failure("The PLAIN response carries no authentication identity.");
            }

            char[] password = SaslEncoding.ToClearableChars(decoded.AsSpan(second + 1));

            return SaslStep.Complete(
                new SaslCredential(authenticationIdentity, authorizationIdentity, password));
        }
        finally
        {
            // The decoded buffer held the password. Clear it whatever happened above.
            Array.Clear(decoded);
        }
    }

    public void Dispose()
    {
        // No state to clear: the decoded buffer is cleared in Decode's finally, and the password
        // now belongs to the SaslCredential the caller disposes.
    }
}

/// <summary>
/// SASL LOGIN, the de facto mechanism.
/// </summary>
/// <remarks>
/// <para>
/// Never standardised, and offered only because a number of clients — Outlook among them —
/// support it and not PLAIN. Two challenges, <c>Username:</c> then <c>Password:</c>, each
/// base64-encoded, each answered with a base64 line.
/// </para>
/// <para>
/// It is strictly worse than PLAIN: an extra round trip for no security benefit, and no
/// authorization identity. It is here for interoperability and for no other reason.
/// </para>
/// </remarks>
public sealed class SaslLoginMechanism : ISaslMechanism
{
    private const string UsernameChallenge = "Username:";
    private const string PasswordChallenge = "Password:";

    private string? _username;
    private Stage _stage = Stage.Start;

    private enum Stage
    {
        Start,
        AwaitingUsername,
        AwaitingPassword,
        Done,
    }

    /// <inheritdoc />
    public string Name => "LOGIN";

    /// <inheritdoc />
    public SaslStep Start(string? initialResponse)
    {
        if (initialResponse is null)
        {
            _stage = Stage.AwaitingUsername;

            return SaslStep.Challenging(SaslEncoding.Encode(UsernameChallenge));
        }

        // Some clients put the username on the AUTH line. Accepting it saves a round trip and
        // costs nothing: it is the same field, arriving earlier.
        if (!TryReadUsername(initialResponse, out SaslStep? failure))
        {
            return failure;
        }

        _stage = Stage.AwaitingPassword;

        return SaslStep.Challenging(SaslEncoding.Encode(PasswordChallenge));
    }

    /// <inheritdoc />
    public SaslStep Advance(string response)
    {
        if (response == SaslEncoding.CancellationToken)
        {
            return SaslStep.Cancelled();
        }

        switch (_stage)
        {
            case Stage.AwaitingUsername:
                if (!TryReadUsername(response, out SaslStep? failure))
                {
                    return failure;
                }

                _stage = Stage.AwaitingPassword;

                return SaslStep.Challenging(SaslEncoding.Encode(PasswordChallenge));

            case Stage.AwaitingPassword:
                return ReadPassword(response);

            default:
                return SaslStep.Failure("LOGIN received a response it did not ask for.");
        }
    }

    private bool TryReadUsername(string response, out SaslStep failure)
    {
        if (response == SaslEncoding.CancellationToken)
        {
            failure = SaslStep.Cancelled();
            return false;
        }

        if (!SaslEncoding.TryDecode(response, out byte[] decoded))
        {
            failure = SaslStep.Failure("The LOGIN username is not valid base64.");
            return false;
        }

        _username = Encoding.UTF8.GetString(decoded);

        Array.Clear(decoded);

        if (_username.Length == 0)
        {
            failure = SaslStep.Failure("The LOGIN username is empty.");
            return false;
        }

        failure = null!;
        return true;
    }

    private SaslStep ReadPassword(string response)
    {
        _stage = Stage.Done;

        if (!SaslEncoding.TryDecode(response, out byte[] decoded))
        {
            return SaslStep.Failure("The LOGIN password is not valid base64.");
        }

        try
        {
            char[] password = SaslEncoding.ToClearableChars(decoded);

            // LOGIN has no authorization identity, so the client is always acting as itself.
            return SaslStep.Complete(new SaslCredential(_username!, string.Empty, password));
        }
        finally
        {
            Array.Clear(decoded);
        }
    }

    public void Dispose() => _username = null;
}

/// <summary>Creates mechanisms by name.</summary>
/// <remarks>
/// A closed set matched exactly. Resolving a mechanism by reflection or by prefix would let a
/// client name something this server never meant to offer.
/// </remarks>
public static class SaslMechanisms
{
    /// <summary>Creates a mechanism, or null when the name is not one this server offers.</summary>
    public static ISaslMechanism? Create(string? name) => name?.ToUpperInvariant() switch
    {
        "PLAIN" => new SaslPlainMechanism(),
        "LOGIN" => new SaslLoginMechanism(),
        _ => null,
    };

    /// <summary>Whether a name is offered. Matches <c>SmtpCapabilities.SaslMechanisms</c>.</summary>
    public static bool IsSupported(string? name) =>
        name is not null &&
        SmtpCapabilities.SaslMechanisms.Contains(name.ToUpperInvariant(), StringComparer.Ordinal);
}
