using System.Text;
using MailServer.Domain.Smtp;

namespace MailServer.Smtp.Tests;

public sealed class SaslPlainTests
{
    /// <summary>Builds a PLAIN response the way a client does.</summary>
    private static string Plain(string authzid, string authcid, string password) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes($"{authzid}\0{authcid}\0{password}"));

    [Fact]
    public void An_initial_response_completes_in_one_step()
    {
        // Most clients send it on the AUTH line. RFC 4954 §4 allows it and it saves a round trip.
        using SaslPlainMechanism mechanism = new();

        SaslStep step = mechanism.Start(Plain(string.Empty, "alice@example.com", "hunter2"));

        step.Outcome.ShouldBe(SaslOutcome.Completed);

        using SaslCredential credential = step.Credential!;

        credential.AuthenticationIdentity.ShouldBe("alice@example.com");
        credential.AuthorizationIdentity.ShouldBe(string.Empty);
        credential.Password.ToString().ShouldBe("hunter2");
    }

    [Fact]
    public void An_absent_initial_response_earns_an_empty_challenge()
    {
        using SaslPlainMechanism mechanism = new();

        SaslStep step = mechanism.Start(initialResponse: null);

        step.Outcome.ShouldBe(SaslOutcome.Challenge);
        step.Challenge.ShouldBe(string.Empty);

        SaslStep completed = mechanism.Advance(Plain(string.Empty, "bob@example.com", "correct horse"));

        completed.Outcome.ShouldBe(SaslOutcome.Completed);

        using SaslCredential credential = completed.Credential!;
        credential.Password.ToString().ShouldBe("correct horse");
    }

    [Fact]
    public void An_equals_sign_is_an_empty_initial_response_not_an_absent_one()
    {
        // RFC 4954 §4 distinguishes them. "=" is a response that happens to be empty, which for
        // PLAIN is malformed rather than a prompt for another line.
        using SaslPlainMechanism mechanism = new();

        mechanism.Start("=").Outcome.ShouldBe(SaslOutcome.Failed);
    }

    [Fact]
    public void An_authorization_identity_is_preserved()
    {
        // A server that dropped it would let a client authenticate as one mailbox and be treated
        // as another, which is the whole point of the field.
        using SaslPlainMechanism mechanism = new();

        SaslStep step = mechanism.Start(Plain("shared@example.com", "alice@example.com", "pw"));

        using SaslCredential credential = step.Credential!;

        credential.AuthorizationIdentity.ShouldBe("shared@example.com");
        credential.AuthenticationIdentity.ShouldBe("alice@example.com");
    }

    [Fact]
    public void A_password_containing_awkward_characters_survives()
    {
        const string Password = "p@ss:w0rd with spaces — ünicode 😀";

        using SaslPlainMechanism mechanism = new();

        SaslStep step = mechanism.Start(Plain(string.Empty, "alice@example.com", Password));

        using SaslCredential credential = step.Credential!;
        credential.Password.ToString().ShouldBe(Password);
    }

    [Fact]
    public void An_empty_password_is_carried_rather_than_rejected_here()
    {
        // Whether an empty password is acceptable is the verifier's decision, not the encoding
        // layer's. Rejecting it here would report "malformed" for what is really "wrong".
        using SaslPlainMechanism mechanism = new();

        SaslStep step = mechanism.Start(Plain(string.Empty, "alice@example.com", string.Empty));

        step.Outcome.ShouldBe(SaslOutcome.Completed);

        using SaslCredential credential = step.Credential!;
        credential.Password.Length.ShouldBe(0);
    }

    [Theory]
    [InlineData("not base64 at all!")]
    [InlineData("****")]
    [InlineData("YWxpY2U=")]                         // one field, no separators
    [InlineData("AGFsaWNl")]                         // one separator only
    public void A_malformed_response_fails_without_throwing(string response)
    {
        // These octets came off the network. A malformed one is an ordinary event that earns a
        // 535, not an exception on the session loop.
        using SaslPlainMechanism mechanism = new();

        mechanism.Start(response).Outcome.ShouldBe(SaslOutcome.Failed);
    }

    [Fact]
    public void An_empty_authentication_identity_is_refused()
    {
        using SaslPlainMechanism mechanism = new();

        mechanism.Start(Plain(string.Empty, string.Empty, "pw")).Outcome.ShouldBe(SaslOutcome.Failed);
    }

    [Fact]
    public void A_client_may_cancel()
    {
        // RFC 4954 §4. A cancelled exchange is not a failed password and must not be counted as
        // one, or a client that changes its mind walks into a lockout.
        using SaslPlainMechanism mechanism = new();

        mechanism.Start(null);

        mechanism.Advance("*").Outcome.ShouldBe(SaslOutcome.Cancelled);
    }

    [Fact]
    public void A_response_that_was_never_asked_for_is_refused()
    {
        using SaslPlainMechanism mechanism = new();

        // Start completed the exchange; there is nothing to advance.
        mechanism.Start(Plain(string.Empty, "alice@example.com", "pw"));

        mechanism.Advance(Plain(string.Empty, "mallory@example.com", "pw")).Outcome
            .ShouldBe(SaslOutcome.Failed);
    }

    [Fact]
    public void An_over_long_response_is_refused_rather_than_decoded()
    {
        // A credential has no business being large, and a mechanism is not the place to discover
        // that someone has sent kilobytes of base64.
        string huge = Convert.ToBase64String(new byte[SaslEncoding.MaxResponseChars * 2]);

        using SaslPlainMechanism mechanism = new();

        mechanism.Start(huge).Outcome.ShouldBe(SaslOutcome.Failed);
    }
}

public sealed class SaslLoginTests
{
    private static string B64(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    [Fact]
    public void The_exchange_is_username_then_password()
    {
        using SaslLoginMechanism mechanism = new();

        SaslStep first = mechanism.Start(initialResponse: null);

        first.Outcome.ShouldBe(SaslOutcome.Challenge);
        Encoding.UTF8.GetString(Convert.FromBase64String(first.Challenge!)).ShouldBe("Username:");

        SaslStep second = mechanism.Advance(B64("alice@example.com"));

        second.Outcome.ShouldBe(SaslOutcome.Challenge);
        Encoding.UTF8.GetString(Convert.FromBase64String(second.Challenge!)).ShouldBe("Password:");

        SaslStep third = mechanism.Advance(B64("hunter2"));

        third.Outcome.ShouldBe(SaslOutcome.Completed);

        using SaslCredential credential = third.Credential!;

        credential.AuthenticationIdentity.ShouldBe("alice@example.com");
        credential.Password.ToString().ShouldBe("hunter2");
    }

    [Fact]
    public void A_username_on_the_auth_line_saves_a_round_trip()
    {
        using SaslLoginMechanism mechanism = new();

        SaslStep first = mechanism.Start(B64("alice@example.com"));

        first.Outcome.ShouldBe(SaslOutcome.Challenge);
        Encoding.UTF8.GetString(Convert.FromBase64String(first.Challenge!)).ShouldBe("Password:");

        using SaslCredential credential = mechanism.Advance(B64("hunter2")).Credential!;
        credential.AuthenticationIdentity.ShouldBe("alice@example.com");
    }

    [Fact]
    public void Login_never_carries_an_authorization_identity()
    {
        // The mechanism has no field for one, so a client is always acting as itself.
        using SaslLoginMechanism mechanism = new();

        mechanism.Start(null);
        mechanism.Advance(B64("alice@example.com"));

        using SaslCredential credential = mechanism.Advance(B64("pw")).Credential!;

        credential.AuthorizationIdentity.ShouldBe(string.Empty);
    }

    [Fact]
    public void A_client_may_cancel_at_either_step()
    {
        using SaslLoginMechanism atUsername = new();
        atUsername.Start(null);
        atUsername.Advance("*").Outcome.ShouldBe(SaslOutcome.Cancelled);

        using SaslLoginMechanism atPassword = new();
        atPassword.Start(null);
        atPassword.Advance(B64("alice@example.com"));
        atPassword.Advance("*").Outcome.ShouldBe(SaslOutcome.Cancelled);
    }

    [Fact]
    public void An_empty_username_is_refused()
    {
        using SaslLoginMechanism mechanism = new();

        mechanism.Start(null);

        mechanism.Advance(B64(string.Empty)).Outcome.ShouldBe(SaslOutcome.Failed);
    }

    [Theory]
    [InlineData("not base64!")]
    [InlineData("%%%%")]
    public void A_malformed_line_fails_without_throwing(string response)
    {
        using SaslLoginMechanism mechanism = new();

        mechanism.Start(null);

        mechanism.Advance(response).Outcome.ShouldBe(SaslOutcome.Failed);
    }

    [Fact]
    public void A_fourth_line_is_refused()
    {
        using SaslLoginMechanism mechanism = new();

        mechanism.Start(null);
        mechanism.Advance(B64("alice@example.com"));
        mechanism.Advance(B64("pw"));

        mechanism.Advance(B64("more")).Outcome.ShouldBe(SaslOutcome.Failed);
    }
}

public sealed class SaslCredentialTests
{
    [Fact]
    public void Disposing_clears_the_password_buffer()
    {
        // A string could not be cleared: immutable, on the managed heap until a collection that
        // may never come, and copyable by compaction on the way.
        char[] password = "hunter2".ToCharArray();

        SaslCredential credential = new("alice@example.com", string.Empty, password);

        credential.Password.ToString().ShouldBe("hunter2");

        credential.Dispose();

        password.ShouldAllBe(c => c == '\0');
    }

    [Fact]
    public void Reading_a_disposed_password_throws_rather_than_returning_stale_memory()
    {
        SaslCredential credential = new("alice@example.com", string.Empty, "pw".ToCharArray());

        credential.Dispose();

        Should.Throw<ObjectDisposedException>(() => credential.Password.ToString());
    }

    [Fact]
    public void Disposing_twice_is_harmless()
    {
        SaslCredential credential = new("alice@example.com", string.Empty, "pw".ToCharArray());

        credential.Dispose();
        credential.Dispose();
    }

    [Fact]
    public void The_credential_type_has_no_finaliser()
    {
        // A credential cleared by a finaliser is cleared at an unpredictable time, which is the
        // same as not being cleared. The Dispose contract is the whole mechanism.
        typeof(SaslCredential)
            .GetMethod("Finalize", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .DeclaringType.ShouldBe(typeof(object));
    }
}

public sealed class SaslMechanismSelectionTests
{
    [Theory]
    [InlineData("PLAIN")]
    [InlineData("plain")]
    [InlineData("Plain")]
    [InlineData("LOGIN")]
    [InlineData("login")]
    public void An_offered_mechanism_resolves_case_insensitively(string name)
    {
        using ISaslMechanism? mechanism = SaslMechanisms.Create(name);

        mechanism.ShouldNotBeNull();
        SaslMechanisms.IsSupported(name).ShouldBeTrue();
    }

    [Theory]
    [InlineData("CRAM-MD5")]
    [InlineData("DIGEST-MD5")]
    [InlineData("SCRAM-SHA-256")]
    [InlineData("EXTERNAL")]
    [InlineData("ANONYMOUS")]
    [InlineData("PLAINTEXT")]
    [InlineData("PLAIN2")]
    [InlineData("")]
    [InlineData(null)]
    public void A_mechanism_this_server_does_not_offer_does_not_resolve(string? name)
    {
        // A closed set matched exactly. Resolving by prefix or by reflection would let a client
        // name something the server never meant to offer - ANONYMOUS most of all.
        SaslMechanisms.Create(name).ShouldBeNull();
        SaslMechanisms.IsSupported(name).ShouldBeFalse();
    }

    [Fact]
    public void Every_advertised_mechanism_can_actually_be_created()
    {
        // Advertising a mechanism the server cannot perform sends clients into a failure they
        // cannot diagnose.
        foreach (string name in SmtpCapabilities.SaslMechanisms)
        {
            using ISaslMechanism? mechanism = SaslMechanisms.Create(name);

            mechanism.ShouldNotBeNull($"'{name}' is advertised but cannot be created.");
            mechanism.Name.ShouldBe(name);
        }
    }

    [Fact]
    public void No_challenge_response_mechanism_is_offered()
    {
        // CRAM-MD5 and DIGEST-MD5 need the server to hold something it can compute a response
        // from - in practice the password. See addendum A5.1.
        foreach (string name in SmtpCapabilities.SaslMechanisms)
        {
            name.ShouldNotContain("CRAM", Case.Insensitive);
            name.ShouldNotContain("DIGEST", Case.Insensitive);
        }
    }
}
