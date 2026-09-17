using MailServer.Domain.Enums;
using MailServer.Domain.Imap;

namespace MailServer.SecurityTests;

/// <summary>
/// Structural and behavioural guarantees of the IMAP implementation.
/// </summary>
/// <remarks>
/// <para>
/// The IMAP counterpart of <see cref="SmtpProtocolSecurityTests"/>, and written now rather than
/// once the listener exists. That test class scans exactly two directories —
/// <c>src/MailServer.Infrastructure/Smtp</c> and <c>src/MailServer.Domain/Smtp</c> — so nothing
/// in this repository currently looks at the IMAP tree at all. A scan added after the code it
/// governs finds whatever is already there and gets weakened until it passes; one added first
/// tells the next implementer what the code may not do, before it does it.
/// </para>
/// <para>
/// <b>The credential rule matters more here than it does for SMTP.</b> SMTP's worst case is
/// <c>AUTH PLAIN &lt;base64&gt;</c> — obfuscated, but a password. IMAP's RFC 3501 §6.2.3
/// <c>LOGIN</c> is <c>a1 LOGIN alice hunter2</c>: the password sits in the command line in the
/// clear, with no encoding at all. A handler that logged
/// <see cref="ImapCommand.Raw"/> at Information would put customer passwords into production
/// logs and into whatever ships them onwards, and today no test in this repository would say so.
/// </para>
/// <para>
/// These assert properties of the shape of the code as well as of its behaviour, for the reason
/// <see cref="SmtpProtocolSecurityTests"/> gives: a behavioural test only covers the paths
/// somebody thought of.
/// </para>
/// </remarks>
public sealed class ImapProtocolSecurityTests
{
    /// <summary>The IMAP implementation's source.</summary>
    /// <remarks>
    /// Located by walking up to the repository root rather than by a relative path from the test
    /// binary, so the tests behave the same whatever the build output layout is. The
    /// Infrastructure directory is permitted to be missing only while the listener has not
    /// landed; the Domain one is not.
    /// </remarks>
    private static IReadOnlyList<string> ImapSourceFiles()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "MailServer.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("Could not find the repository root from the test binary.");

        string domainRoot = Path.Combine(directory.FullName, "src", "MailServer.Domain", "Imap");
        string infrastructureRoot = Path.Combine(directory.FullName, "src", "MailServer.Infrastructure", "Imap");

        Directory.Exists(domainRoot).ShouldBeTrue($"Expected IMAP domain sources at {domainRoot}.");
        Directory.Exists(infrastructureRoot).ShouldBeTrue(
            $"Expected IMAP infrastructure sources at {infrastructureRoot}.");

        List<string> files =
        [
            .. Directory.EnumerateFiles(domainRoot, "*.cs", SearchOption.AllDirectories),
            .. Directory.EnumerateFiles(infrastructureRoot, "*.cs", SearchOption.AllDirectories),
        ];

        files.ShouldNotBeEmpty();

        return files;
    }

    /// <summary>A file's executable source, with whole-line comments removed.</summary>
    /// <remarks>
    /// The scans below look for constructs that would be dangerous if the compiler saw them. A
    /// comment explaining why such a construct is deliberately absent is not one of them, and a
    /// scan that could not tell the difference would push exactly that explanation out of the
    /// code.
    /// </remarks>
    private static string ExecutableSource(string file)
    {
        IEnumerable<string> lines = File
            .ReadAllLines(file)
            .Where(line => !line.TrimStart().StartsWith("//", StringComparison.Ordinal));

        return string.Join('\n', lines);
    }

    [Fact]
    public void The_scan_covers_the_imap_source_tree()
    {
        // A vacuity guard. A scan that silently found no files would pass every test below while
        // asserting nothing at all.
        IReadOnlyList<string> files = ImapSourceFiles();

        files.Count.ShouldBeGreaterThan(4);
        files.ShouldContain(f => Path.GetFileName(f) == "ImapCommand.cs");
        files.ShouldContain(f => Path.GetFileName(f) == "ImapLineReader.cs");
    }

    // ---------------------------------------------------------------------------------------
    // Rule 77: never log or echo a credential. IMAP's LOGIN is cleartext, not base64.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void No_imap_source_logs_a_raw_command_line_at_information_level_or_above()
    {
        // "a1 LOGIN alice hunter2" is a raw command line. Unlike SMTP's AUTH, nothing about it
        // is encoded, so logging one at a level that reaches production logs writes the password
        // down verbatim.
        foreach (string file in ImapSourceFiles())
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

                    line.ShouldNotContain(
                        ".Argument",
                        Case.Insensitive,
                        $"{Path.GetFileName(file)} logs a command argument at {level}; " +
                        "LOGIN's argument is a username and a cleartext password.");
                }
            }
        }
    }

    [Theory]
    [InlineData("a1 LOGIN alice hunter2")]
    [InlineData("a1 login alice hunter2")]
    [InlineData("a1 AUTHENTICATE PLAIN AGFsaWNlAGh1bnRlcjI=")]
    public void Rendering_a_command_never_reveals_a_credential(string line)
    {
        // The exposure the scan above cannot see. A record's generated ToString prints every
        // property, so "logger.LogWarning("Unexpected command {Command}", command)" would write
        // the password down while mentioning neither Raw nor Argument by name - the source scan
        // matches on those two identifiers and would pass that line without comment.
        ImapCommand.TryParse(line, out ImapCommand? command, out _).ShouldBeTrue();

        foreach (string rendered in (string[])[command!.ToString(), $"{command}", string.Format(
                     System.Globalization.CultureInfo.InvariantCulture, "{0}", command)])
        {
            rendered.ShouldNotContain("hunter2", Case.Insensitive, rendered);
            rendered.ShouldNotContain("AGFsaWNlAGh1bnRlcjI=", Case.Insensitive, rendered);
            rendered.ShouldNotContain(command.Argument, Case.Insensitive, rendered);
            rendered.ShouldNotContain(command.Raw, Case.Insensitive, rendered);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Rule 105: no certificate validation bypass.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void The_imap_tls_path_installs_no_certificate_validation_callback()
    {
        // This server is the TLS server on every IMAP connection, without exception — there is
        // no IMAP equivalent of the outbound delivery client, because nothing here ever connects
        // out over IMAP. So a validation callback anywhere in this tree validates nothing that
        // needs validating, and is simply the obvious place for somebody debugging a handshake
        // to write "return true" and never take it out again.
        foreach (string file in ImapSourceFiles())
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
    public void The_imap_tls_path_does_not_offer_a_withdrawn_protocol_version()
    {
        // TLS 1.0 and 1.1 are withdrawn. Offering them lets an attacker downgrade a session that
        // would otherwise have been fine — and on port 993 the whole session, credentials
        // included, is inside that downgraded tunnel.
        foreach (string file in ImapSourceFiles())
        {
            string source = ExecutableSource(file);

            foreach (string withdrawn in (string[])
                     ["SslProtocols.Tls11", "SslProtocols.Ssl3", "SslProtocols.Ssl2", "SslProtocols.Tls |", "SslProtocols.Tls;"])
            {
                source.ShouldNotContain(
                    withdrawn,
                    Case.Sensitive,
                    $"{Path.GetFileName(file)} offers a withdrawn TLS version.");
            }
        }
    }

    // ---------------------------------------------------------------------------------------
    // No plaintext credentials: the capability listing is the enforcement point.
    // ---------------------------------------------------------------------------------------

    public static TheoryData<ImapListenerRole, bool, ImapSessionState> EveryConnectionShape()
    {
        TheoryData<ImapListenerRole, bool, ImapSessionState> data = [];

        foreach (ImapListenerRole role in Enum.GetValues<ImapListenerRole>())
        {
            foreach (bool tls in new[] { false, true })
            {
                foreach (ImapSessionState state in Enum.GetValues<ImapSessionState>())
                {
                    data.Add(role, tls, state);
                }
            }
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(EveryConnectionShape))]
    public void No_authentication_mechanism_is_ever_advertised_without_tls(
        ImapListenerRole role,
        bool tls,
        ImapSessionState state)
    {
        // RFC 2595 section 9: PLAIN "MUST NOT be advertised or used unless a suitable TLS
        // encryption layer is active". Asserted over every connection shape rather than the one
        // the capability tests happen to exercise, because this is the property that keeps a
        // password off the wire.
        IReadOnlyList<string> capabilities =
            ImapCapabilities.For(new ImapCapabilityContext(role, tls, state, IsAuthenticationAvailable: true));

        if (!tls)
        {
            capabilities.ShouldNotContain(
                c => c.StartsWith("AUTH=", StringComparison.Ordinal),
                $"role {role}, state {state} offered a mechanism in the clear.");
        }
    }

    [Theory]
    [MemberData(nameof(EveryConnectionShape))]
    public void A_cleartext_connection_is_always_told_that_login_is_refused(
        ImapListenerRole role,
        bool tls,
        ImapSessionState state)
    {
        // RFC 2595 section 3.2 makes this a MUST, and it is the half of the defence SMTP does
        // not need: LOGIN is a mandatory IMAP4rev1 command, so a client that is told nothing
        // assumes it may use it. Silence is what SMTP can rely on; IMAP cannot.
        IReadOnlyList<string> capabilities =
            ImapCapabilities.For(new ImapCapabilityContext(role, tls, state, IsAuthenticationAvailable: true));

        if (!tls && state == ImapSessionState.NotAuthenticated)
        {
            capabilities.ShouldContain("LOGINDISABLED");
        }
    }

    [Theory]
    [MemberData(nameof(EveryConnectionShape))]
    public void The_refusal_and_a_mechanism_are_never_advertised_at_once(
        ImapListenerRole role,
        bool tls,
        ImapSessionState state)
    {
        // Obeying RFC 2595 section 3.2 while still offering AUTH=PLAIN in the clear would
        // advertise the refusal and leak the password through the other command anyway.
        IReadOnlyList<string> capabilities =
            ImapCapabilities.For(new ImapCapabilityContext(role, tls, state, IsAuthenticationAvailable: true));

        bool refused = capabilities.Contains("LOGINDISABLED");
        bool offered = capabilities.Any(c => c.StartsWith("AUTH=", StringComparison.Ordinal));

        (refused && offered).ShouldBeFalse($"role {role}, tls {tls}, state {state} advertised both.");
    }

    [Fact]
    public void The_session_refuses_to_authenticate_without_tls()
    {
        // The last line of defence, below the capability listing. A defence that depends only on
        // never advertising the mechanism is one bug in the advertiser away from not being one.
        ImapSessionContext session = new(
            Domain.ValueObjects.IpAddressValue.Parse("198.51.100.7"),
            DateTimeOffset.UtcNow,
            isTlsActive: false);

        Should.Throw<InvalidOperationException>(
            () => session.Authenticate(
                new Domain.ValueObjects.MailboxId(Guid.NewGuid()),
                Domain.ValueObjects.EmailAddress.Parse("alice@example.com")));
    }

    // ---------------------------------------------------------------------------------------
    // Response splitting: no client-supplied text can add a line to the response stream.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// Text shaped to break out of a response, in the ways a hostile client would try.
    /// </summary>
    /// <remarks>
    /// The payloads forge the responses that actually cost a user something: an
    /// <c>EXPUNGE</c> makes a caching client delete mail from its local store, an
    /// <c>EXISTS</c> of zero empties the mailbox, a changed <c>UIDVALIDITY</c> invalidates every
    /// cache, and a tagged completion carrying another in-flight command's tag reports a success
    /// that never happened.
    /// </remarks>
    public static TheoryData<string> HostileText() =>
    [
        "ok\r\n* 1 EXPUNGE",
        "ok\n* 1 EXPUNGE",
        "ok\r* 1 EXPUNGE",
        "ok\r\n* 0 EXISTS",
        "ok\r\n* OK [UIDVALIDITY 1] hijacked",
        "ok\r\nA002 OK STORE completed",
        "ok\r\n+ send me a literal",
        "\r\n\r\n\r\n",
        "\u0000\r\n* 1 EXPUNGE",
        "ok\u0085* 1 EXPUNGE",
        "ok\u2028* 1 EXPUNGE",
        "ok\u2029* 1 EXPUNGE",
    ];

    [Theory]
    [MemberData(nameof(HostileText))]
    public void No_response_text_can_produce_a_second_line(string hostile)
    {
        // Response text routinely quotes something the client sent - a mailbox name that would
        // not decode, an unrecognised command, a malformed sequence set - and several of those
        // arrive before LOGIN, from a peer that has proven nothing.
        ImapResponse[] responses =
        [
            ImapResponse.Tagged("A001", ImapResponseStatus.No, hostile),
            ImapResponse.Tagged("A001", ImapResponseStatus.Bad, hostile),
            ImapResponse.Untagged(ImapResponseStatus.Ok, hostile),
            ImapResponse.Data(hostile),
            ImapResponse.Continuation(hostile),
            ImapResponses.UntaggedBad(hostile),
            ImapResponses.Bye(hostile),
        ];

        foreach (ImapResponse response in responses)
        {
            string formatted = response.Format();

            formatted.ShouldEndWith("\r\n");
            formatted.Count(c => c == '\r').ShouldBe(1, $"'{formatted}' carries a stray CR.");
            formatted.Count(c => c == '\n').ShouldBe(1, $"'{formatted}' carries a stray LF.");
            formatted[..^2].ShouldNotContain("\r", Case.Sensitive);
            formatted[..^2].ShouldNotContain("\n", Case.Sensitive);
        }
    }

    [Theory]
    [MemberData(nameof(HostileText))]
    public void No_response_code_argument_can_produce_a_second_line(string hostile)
    {
        // A response code is one nesting level down and has its own escape: RFC 3501 section 9
        // excludes "]" from the argument because a bracket would close the code early, after
        // which the client reads the remainder as ordinary text.
        ImapResponseCode code = new("BADCHARSET", hostile + "] injected");

        string formatted = ImapResponse.Tagged("A001", ImapResponseStatus.No, "bad charset", code).Format();

        formatted.ShouldEndWith("\r\n");
        formatted.Count(c => c == '\n').ShouldBe(1);
        // Exactly one bracket pair: the one the writer itself opened and closed. A bracket the
        // argument contributed would have closed the code early, and everything after it would
        // be read by the client as ordinary text.
        // Only ']' closes a response code. RFC 3501 section 9's argument production is
        // 1*<any TEXT-CHAR except "]">, so an opening bracket inside the argument is legal and
        // harmless - it is the closing one that would end the code early, after which the
        // client reads the remainder as ordinary text.
        formatted.Count(c => c == ']').ShouldBe(1, formatted);
        formatted.ShouldEndWith("] bad charset\r\n");
    }

    [Theory]
    [MemberData(nameof(HostileText))]
    public void Every_formatted_response_is_seven_bit(string hostile)
    {
        // RFC 3501 section 9: TEXT-CHAR is CHAR minus CR and LF, and CHAR is %x01-7F. Stricter
        // than the SMTP rule, which lets 8-bit through because SMTPUTF8 exists. This server does
        // not advertise RFC 6855 UTF8=ACCEPT, so anything above 0x7E is ungrammatical.
        string formatted = ImapResponse.Untagged(ImapResponseStatus.No, hostile).Format();

        foreach (char c in formatted[..^2])
        {
            (c is >= (char)0x20 and <= (char)0x7E).ShouldBeTrue(
                $"U+{(int)c:X4} is outside printable US-ASCII.");
        }
    }

    [Theory]
    [MemberData(nameof(HostileText))]
    public void A_response_never_ends_in_a_bare_space(string hostile)
    {
        // RFC 3501 section 9's text is 1*TEXT-CHAR. Text that sanitises away to nothing would
        // otherwise produce a line that is not a response at all, and a client's parser is
        // entitled to reject it.
        ImapResponse.Untagged(ImapResponseStatus.No, hostile).Format().ShouldNotEndWith(" \r\n");
    }

    // ---------------------------------------------------------------------------------------
    // The tag: validated on the way in, refused on the way out.
    // ---------------------------------------------------------------------------------------

    /// <summary>Tags a hostile client would try, each rejected for a different reason.</summary>
    public static TheoryData<string> HostileTags() =>
    [
        "A\r\nB",
        "A\rB",
        "A\nB",
        "A\u0000B",
        "A\u007fB",
        "*",
        "+",
        "A+B",
        "A\"B",
        "A\\B",
        "A(B",
        "A)B",
        "A{B",
        "A%B",
        "A*B",
        "",
    ];

    [Theory]
    [MemberData(nameof(HostileTags))]
    public void A_hostile_tag_never_parses(string tag)
    {
        // RFC 3501 section 9's tag production excludes CTL, which is what keeps a CR out of text
        // this server is about to echo. ImapLineReader strips only the CR immediately before a
        // line's terminating LF, so a CR in the middle of a tag arrives intact.
        ImapCommand.TryParse($"{tag} NOOP", out ImapCommand? command, out ImapTagFailure failure)
            .ShouldBeFalse($"'{tag}' was accepted as a tag.");

        command.ShouldBeNull();
        failure.ShouldNotBe(ImapTagFailure.None);
    }

    [Theory]
    [MemberData(nameof(HostileTags))]
    public void A_hostile_tag_can_never_be_echoed(string tag)
    {
        // Refused rather than sanitised, so the hostile bytes never enter the output stream at
        // all. Repairing a tag would be worse than useless: the client byte-matches the tagged
        // completion against the command it issued, so a repaired tag is a completion it cannot
        // match, and it waits for one that never comes.
        Should.Throw<ArgumentException>(
            () => ImapResponse.Tagged(tag, ImapResponseStatus.Ok, "completed"),
            $"'{tag}' was echoed back into a response.");
    }

    [Fact]
    public void An_over_long_tag_is_refused_rather_than_amplified()
    {
        // Every tagged response repeats the tag, and a pipelining client can have many commands
        // in flight at once. Without a cap, an unauthenticated peer buys output and log
        // amplification for the cost of one long line.
        string tag = new('A', ImapCommand.MaxTagLength + 1);

        ImapCommand.TryParse($"{tag} NOOP", out _, out ImapTagFailure failure).ShouldBeFalse();
        failure.ShouldBe(ImapTagFailure.TooLong);

        Should.Throw<ArgumentException>(() => ImapResponse.Tagged(tag, ImapResponseStatus.Ok, "ok"));
    }

    // ---------------------------------------------------------------------------------------
    // Sequencing: nothing that needs an identity is reachable without one.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void No_command_touching_a_mailbox_is_in_sequence_before_authentication()
    {
        // The state machine is the one place this is decided, so this asserts the whole class of
        // commands rather than the handful a behavioural test would reach. Anything that reads,
        // writes, lists or deletes mail needs an identity first.
        ImapVerb[] needAnIdentity =
        [
            ImapVerb.Select, ImapVerb.Examine, ImapVerb.Create, ImapVerb.Delete, ImapVerb.Rename,
            ImapVerb.Subscribe, ImapVerb.Unsubscribe, ImapVerb.List, ImapVerb.Lsub,
            ImapVerb.Status, ImapVerb.Append, ImapVerb.Check, ImapVerb.Close, ImapVerb.Expunge,
            ImapVerb.Search, ImapVerb.Fetch, ImapVerb.Store, ImapVerb.Copy, ImapVerb.Move,
            ImapVerb.Unselect, ImapVerb.Idle, ImapVerb.Namespace,
        ];

        foreach (ImapVerb verb in needAnIdentity)
        {
            ImapStateMachine.IsInSequence(ImapSessionState.NotAuthenticated, verb).ShouldBeFalse(
                $"{verb} is reachable before LOGIN.");
        }
    }

    [Theory]
    [InlineData(ImapSessionState.Authenticated)]
    [InlineData(ImapSessionState.Selected)]
    public void A_session_cannot_re_authenticate_as_somebody_else(ImapSessionState state)
    {
        // Enforced in two places on purpose. A rule held in one place only is one bug away from
        // an account takeover, and this one would hand an attacker another user's mail on a
        // connection that had already passed every check.
        ImapStateMachine.IsInSequence(state, ImapVerb.Login).ShouldBeFalse();
        ImapStateMachine.IsInSequence(state, ImapVerb.Authenticate).ShouldBeFalse();

        ImapSessionContext session = new(
            Domain.ValueObjects.IpAddressValue.Parse("198.51.100.7"),
            DateTimeOffset.UtcNow,
            isTlsActive: true);

        session.Authenticate(
            new Domain.ValueObjects.MailboxId(Guid.NewGuid()),
            Domain.ValueObjects.EmailAddress.Parse("alice@example.com"));

        Should.Throw<InvalidOperationException>(
            () => session.Authenticate(
                new Domain.ValueObjects.MailboxId(Guid.NewGuid()),
                Domain.ValueObjects.EmailAddress.Parse("mallory@example.com")));
    }

    [Fact]
    public void A_failed_authentication_attempt_can_never_be_bought_back()
    {
        // The counter is this server's own accounting of the connection, not something the
        // client told it, so nothing the client does may reset it. A counter a client could
        // clear is an unlimited password-guessing budget.
        ImapSessionContext session = new(
            Domain.ValueObjects.IpAddressValue.Parse("198.51.100.7"),
            DateTimeOffset.UtcNow,
            isTlsActive: true);

        session.RecordFailedAuthentication().ShouldBe(1);
        session.RecordFailedAuthentication().ShouldBe(2);

        session.Authenticate(
            new Domain.ValueObjects.MailboxId(Guid.NewGuid()),
            Domain.ValueObjects.EmailAddress.Parse("alice@example.com"));

        session.Deselect();
        session.Logout();

        session.FailedAuthenticationAttempts.ShouldBe(2);
    }

    // ---------------------------------------------------------------------------------------
    // Resource exhaustion: every bound a client can push against is a fixed one.
    // ---------------------------------------------------------------------------------------

    [Fact]
    public void A_sequence_set_never_materialises_the_numbers_a_range_names()
    {
        // "1:*" is two bytes on the wire and legal against a mailbox whose UIDNEXT has climbed
        // into the billions over years of delivery and expunging. Resolving it must produce
        // bounds, never a list.
        ImapSequenceSet.TryParse("1:*", out ImapSequenceSet? set).ShouldBeTrue();

        IReadOnlyList<(long Start, long End)> resolved = set!.Resolve(maxValue: 4_000_000_000);

        resolved.Count.ShouldBe(1);
        resolved[0].ShouldBe((1L, 4_000_000_000L));
    }

    [Fact]
    public void A_sequence_set_with_more_segments_than_the_cap_is_refused()
    {
        // The text itself, not merely what it resolves to, is attacker-controlled input from an
        // unauthenticated-until-LOGIN connection.
        string tooMany = string.Join(',', Enumerable.Range(1, ImapSequenceSet.MaxSegments + 1));

        ImapSequenceSet.TryParse(tooMany, out _).ShouldBeFalse();
    }

    [Fact]
    public void A_non_synchronising_literal_is_parsed_without_being_trusted()
    {
        // RFC 7888's "{n+}" lets a client send the byte count and the bytes together, with no
        // round trip in between. Parsing the specifier must never imply accepting the count:
        // the cap lives where the octets are actually read.
        ImapLiteralSpecifier.TryParse("{4000000000+}", out ImapLiteralSpecifier specifier).ShouldBeTrue();

        specifier.ByteCount.ShouldBe(4_000_000_000L);
        specifier.IsSynchronizing.ShouldBeFalse();
    }

    [Theory]
    [InlineData("{-1}")]
    [InlineData("{+1}")]
    [InlineData("{ 1}")]
    [InlineData("{1 }")]
    [InlineData("{1,000}")]
    [InlineData("{0x10}")]
    public void A_literal_specifier_accepts_only_strict_digits(string text)
    {
        // Everything long.TryParse's default NumberStyles would otherwise tolerate is a way to
        // declare one size and be read as another.
        ImapLiteralSpecifier.TryParse(text, out _).ShouldBeFalse();
    }

    [Fact]
    public void A_malformed_mailbox_name_is_refused_rather_than_guessed_at()
    {
        // The wire text arrives in a SELECT, CREATE or RENAME argument before the client has
        // necessarily proven anything about itself. Guessing at what a malformed encoding meant
        // is how one user reaches another user's folder.
        // An unrecognised character in the shift sequence, and non-zero leftover padding bits a
        // correct encoder would never have produced. ("&AAA" is NOT malformed - it is a
        // well-formed encoding of U+0000, which is a different problem for a different layer.)
        ImapMailboxName.TryDecode("&Jj_-", out _).ShouldBeFalse();
        ImapMailboxName.TryDecode("&JjoB-", out _).ShouldBeFalse();

        ImapMailboxName.TryDecode("&Jjo-", out string? valid).ShouldBeTrue();
        valid.ShouldBe("☺");
    }
}
