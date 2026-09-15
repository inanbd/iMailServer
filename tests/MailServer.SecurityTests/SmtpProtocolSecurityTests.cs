using System.Reflection;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Domain.Enums;
using MailServer.Domain.Smtp;
using MailServer.Infrastructure.Smtp;

namespace MailServer.SecurityTests;

/// <summary>
/// Structural guarantees of the SMTP implementation.
/// </summary>
/// <remarks>
/// These assert properties of the shape of the code rather than of its behaviour, because a
/// behavioural test can only cover the paths somebody thought of. A source scan that fails the
/// build catches the path nobody thought of, in a file nobody reviewed, on a Friday.
/// </remarks>
public sealed class SmtpProtocolSecurityTests
{
    /// <summary>The SMTP implementation's source, for scans that need to read it.</summary>
    /// <remarks>
    /// Located by walking up to the repository root rather than by a relative path from the test
    /// binary, so the tests behave the same whatever the build output layout is.
    /// </remarks>
    private static IReadOnlyList<string> SmtpSourceFiles()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "MailServer.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("Could not find the repository root from the test binary.");

        string[] roots =
        [
            Path.Combine(directory.FullName, "src", "MailServer.Infrastructure", "Smtp"),
            Path.Combine(directory.FullName, "src", "MailServer.Domain", "Smtp"),
        ];

        List<string> files = [];

        foreach (string root in roots)
        {
            Directory.Exists(root).ShouldBeTrue($"Expected SMTP sources at {root}.");

            files.AddRange(Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories));
        }

        files.ShouldNotBeEmpty();

        return files;
    }

    /// <summary>
    /// A file's executable source, with comments removed.
    /// </summary>
    /// <remarks>
    /// The scans below look for constructs that would be dangerous if the compiler saw them. A
    /// comment explaining why such a construct is deliberately absent is not one of them, and a
    /// scan that could not tell the difference would push exactly that explanation out of the
    /// code — leaving the next reader to wonder why there is no callback and add one.
    /// </remarks>
    private static string ExecutableSource(string file)
    {
        IEnumerable<string> lines = File
            .ReadAllLines(file)
            .Where(line => !line.TrimStart().StartsWith("//", StringComparison.Ordinal));

        return string.Join('\n', lines);
    }

    // ---------------------------------------------------------------------------------------
    // Rule 105: no certificate validation bypass.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_smtp_tls_path_installs_no_certificate_validation_callback()
    {
        // This server is the TLS server on these connections, so it validates nothing and needs
        // no callback. The danger is the callback EXISTING: it is the obvious place for somebody
        // debugging a handshake to write "return true" and never take it out again.
        foreach (string file in SmtpSourceFiles())
        {
            string source = ExecutableSource(file);

            source.ShouldNotContain(
                "RemoteCertificateValidationCallback",
                Case.Insensitive,
                $"{Path.GetFileName(file)} installs a certificate validation callback.");

            source.ShouldNotContain(
                "ServerCertificateValidationCallback",
                Case.Insensitive,
                $"{Path.GetFileName(file)} installs a certificate validation callback.");
        }
    }

    [Fact]
    public void The_smtp_tls_path_does_not_offer_a_withdrawn_protocol_version()
    {
        // TLS 1.0 and 1.1 are withdrawn. Offering them lets an attacker downgrade a session that
        // would otherwise have been fine.
        foreach (string file in SmtpSourceFiles())
        {
            string source = ExecutableSource(file);

            source.ShouldNotContain("SslProtocols.Tls11", customMessage: $"{Path.GetFileName(file)} offers TLS 1.1.");
            source.ShouldNotContain("SslProtocols.Ssl3", customMessage: $"{Path.GetFileName(file)} offers SSL 3.");

            // "SslProtocols.Tls" on its own is TLS 1.0, and is easy to write by accident when
            // reaching for the enum. Matched with its delimiters so Tls12 and Tls13 do not hit.
            source.ShouldNotContain("SslProtocols.Tls |", customMessage: $"{Path.GetFileName(file)} offers TLS 1.0.");
            source.ShouldNotContain("SslProtocols.Tls;", customMessage: $"{Path.GetFileName(file)} offers TLS 1.0.");
        }
    }

    // ---------------------------------------------------------------------------------------
    // Rule 105: no unbounded network reads, no unlimited message sizes.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_line_reader_allocates_from_its_limit_and_never_grows()
    {
        // The buffer is allocated once from MaxLineOctets and never replaced. A peer that sends
        // gigabytes without a line ending causes exactly that much allocation and then a refusal.
        FieldInfo[] fields = typeof(SmtpLineReader)
            .GetFields(BindingFlags.NonPublic | BindingFlags.Instance);

        FieldInfo buffer = fields.Single(f => f.FieldType == typeof(byte[]));

        buffer.IsInitOnly.ShouldBeTrue(
            "The line reader's buffer is not readonly, so something can replace it with a larger " +
            "one. The fixed buffer IS the bound on the read.");

        // And nothing that grows: no list of chunks, no MemoryStream, no StringBuilder holding
        // the line while it waits for a terminator.
        foreach (FieldInfo field in fields)
        {
            field.FieldType.ShouldNotBe(typeof(MemoryStream));
            field.FieldType.ShouldNotBe(typeof(System.Text.StringBuilder));
            field.FieldType.Name.ShouldNotStartWith("List`");
        }
    }

    [Fact]
    public void The_message_store_offers_no_way_to_hold_a_whole_message()
    {
        // docs/SMTP.md: the API surface enforces the rule. An overload returning the whole
        // message would eventually be called on a thirty-megabyte one from a stranger.
        foreach (Type type in (Type[])[typeof(IMessageStore), typeof(IMessageWriter)])
        {
            foreach (MethodInfo method in type.GetMethods())
            {
                method.ReturnType.ToString().ShouldNotContain(
                    "System.Byte[]",
                    customMessage: $"{type.Name}.{method.Name} hands back a whole message as an array.");
            }
        }
    }

    [Fact]
    public void The_data_receiver_bounds_how_far_past_the_limit_a_peer_may_run()
    {
        // Reading on to the end-of-data marker after refusing an over-size message is a courtesy
        // to the sender. Without a budget it is the unbounded read rule 105 forbids.
        SmtpDataReceiver.MaxOverrunBytes.ShouldBeGreaterThan(0);
        SmtpDataReceiver.MaxOverrunBytes.ShouldBeLessThanOrEqualTo(16L * 1024 * 1024);
    }

    // ---------------------------------------------------------------------------------------
    // Rule 105: no plaintext SMTP AUTH over Internet.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void Auth_is_never_advertised_on_port_25_in_any_configuration()
    {
        // Every combination of the flags that could possibly turn it on.
        foreach (bool tls in (bool[])[false, true])
        {
            foreach (bool available in (bool[])[false, true])
            {
                SmtpCapabilityContext context = new(
                    SmtpListenerRole.InboundMta,
                    tls,
                    available,
                    MaxMessageSizeBytes: 1_000_000,
                    IsSmtpUtf8Available: true,
                    IsChunkingAvailable: true);

                SmtpCapabilities.MayOfferAuthentication(context).ShouldBeFalse(
                    $"AUTH was offered on the MTA listener with TLS {tls}, available {available}.");

                SmtpCapabilities.For(context).ShouldNotContain(
                    c => c.StartsWith("AUTH", StringComparison.Ordinal));
            }
        }
    }

    [Fact]
    public void Auth_is_never_advertised_before_tls_on_any_listener()
    {
        foreach (SmtpListenerRole role in Enum.GetValues<SmtpListenerRole>())
        {
            SmtpCapabilityContext context = new(
                role,
                IsTlsActive: false,
                IsAuthenticationAvailable: true,
                MaxMessageSizeBytes: 1_000_000);

            SmtpCapabilities.MayOfferAuthentication(context).ShouldBeFalse(
                $"AUTH was offered before TLS on {role}.");
        }
    }

    [Fact]
    public void The_session_refuses_to_record_an_authentication_that_happened_without_tls()
    {
        // The last line of defence behind capability advertisement. A defence that depends on
        // another component being correct is not a defence.
        SmtpSessionContext session = new(
            SmtpListenerRole.Submission,
            MailServer.Domain.ValueObjects.IpAddressValue.Parse("198.51.100.20"),
            DateTimeOffset.UtcNow,
            isTlsActive: false);

        Should.Throw<InvalidOperationException>(() =>
            session.Authenticate(MailServer.Domain.ValueObjects.EmailAddress.Parse("user@example.com")));

        session.IsAuthenticated.ShouldBeFalse();
    }

    // ---------------------------------------------------------------------------------------
    // STARTTLS: the reset, and the buffer that carries the injection.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_handshake_discards_every_piece_of_state_the_client_supplied()
    {
        SmtpSessionContext session = new(
            SmtpListenerRole.Submission,
            MailServer.Domain.ValueObjects.IpAddressValue.Parse("198.51.100.20"),
            DateTimeOffset.UtcNow,
            isTlsActive: false);

        session.Greet("attacker.example", extended: true);
        session.BeginTransaction(MailServer.Domain.ValueObjects.EmailAddress.Parse("a@b.example"), 4096);
        session.AcceptRecipient(
            MailServer.Domain.ValueObjects.EmailAddress.Parse("victim@example.com"),
            RelayDecision.AcceptLocal);

        session.CompleteTlsHandshake();

        session.GreetedName.ShouldBeNull();
        session.UsedExtendedGreeting.ShouldBeFalse();
        session.HasTransaction.ShouldBeFalse();
        session.ReversePath.ShouldBeNull();
        session.DeclaredMessageSize.ShouldBeNull();
        session.Recipients.ShouldBeEmpty();
        session.IsAuthenticated.ShouldBeFalse();
        session.State.ShouldBe(SmtpSessionState.Connected);
    }

    [Fact]
    public void The_reader_can_report_and_drop_what_it_read_ahead()
    {
        // The other half of the STARTTLS bug. A session cannot honour RFC 3207's discard
        // requirement unless it can see what the reader buffered, and cannot treat pipelining
        // across the handshake as the attack it is unless the reader says how much there was.
        MethodInfo[] methods = typeof(SmtpLineReader).GetMethods();

        methods.ShouldContain(
            m => m.Name == nameof(SmtpLineReader.DiscardBufferedInput),
            "The reader cannot discard what it read before the handshake.");

        typeof(SmtpLineReader).GetProperty(nameof(SmtpLineReader.BufferedOctetCount))
            .ShouldNotBeNull("The session cannot tell whether the peer pipelined across STARTTLS.");
    }

    [Fact]
    public void Starttls_is_never_offered_once_tls_is_active()
    {
        // RFC 3207 §4.2. A nested handshake inside an existing session is not something SMTP
        // does, and offering it invites a client to try.
        foreach (SmtpListenerRole role in Enum.GetValues<SmtpListenerRole>())
        {
            SmtpCapabilityContext context = new(
                role,
                IsTlsActive: true,
                IsAuthenticationAvailable: true,
                MaxMessageSizeBytes: 1_000_000);

            SmtpCapabilities.MayOfferStartTls(context).ShouldBeFalse($"STARTTLS was offered inside TLS on {role}.");
            SmtpCapabilities.For(context).ShouldNotContain("STARTTLS");
        }
    }

    // ---------------------------------------------------------------------------------------
    // SMTP smuggling.
    // ---------------------------------------------------------------------------------------

    [Theory]
    [InlineData("\n.\n")]
    [InlineData("\r\n.\n")]
    [InlineData("\n.\r\n")]
    [InlineData("\r.\r\n")]
    public void Only_the_exact_marker_ends_a_message(string nearMiss)
    {
        // SMTP smuggling (2023). A server that accepts a near-miss while the next hop accepts
        // only the real thing - or the reverse - lets an attacker append a forged message to a
        // legitimate one.
        SmtpDataDecoder decoder = new();

        byte[] input = System.Text.Encoding.UTF8.GetBytes(
            $"legitimate{nearMiss}MAIL FROM:<attacker@evil.example>\r\n.\r\n");

        byte[] output = new byte[SmtpDataDecoder.MaxOutputFor(input.Length)];

        decoder.Decode(input, output, out int consumed, out int written).ShouldBeTrue();

        consumed.ShouldBe(input.Length, "The message was truncated at a sequence that is not a marker.");

        System.Text.Encoding.UTF8.GetString(output, 0, written).ShouldContain(
            "MAIL FROM:<attacker@evil.example>",
            customMessage: "The injected command must be message content, never a command.");
    }

    // ---------------------------------------------------------------------------------------
    // Rule 77: never log or echo a credential.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void No_smtp_source_logs_a_raw_command_line_at_information_level_or_above()
    {
        // A raw command line can be "AUTH PLAIN <base64 password>". Logging one at a level that
        // reaches production logs puts customer passwords in them, and in whatever ships them
        // onwards.
        foreach (string file in SmtpSourceFiles())
        {
            string source = ExecutableSource(file);

            foreach (string level in (string[])["LogInformation", "LogWarning", "LogError", "LogCritical"])
            {
                foreach (string line in source.Split('\n'))
                {
                    if (!line.Contains(level, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    line.ShouldNotContain(
                        "command.Raw",
                        Case.Insensitive,
                        $"{Path.GetFileName(file)} logs a raw command line at {level}.");

                    line.ShouldNotContain(
                        "line.Text",
                        Case.Insensitive,
                        $"{Path.GetFileName(file)} logs a raw command line at {level}.");
                }
            }
        }
    }

    [Fact]
    public void No_reply_in_the_vocabulary_echoes_an_authentication_argument()
    {
        // The base64 blob after AUTH is a password. A reply that quoted the command back would
        // put it in the peer's logs, any intermediary's logs, and a packet capture.
        const string Credential = "AGFsaWNlAGh1bnRlcjI=";

        SmtpReply[] replies =
        [
            SmtpReplies.AuthenticationRequired(),
            SmtpReplies.AuthenticationFailed(),
            SmtpReplies.TlsRequired(),
            SmtpReplies.CommandNotImplemented("AUTH"),
        ];

        foreach (SmtpReply reply in replies)
        {
            reply.Format().ShouldNotContain(Credential);
            reply.Format().ShouldNotContain("alice", Case.Insensitive);
        }
    }
}
