using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;

namespace MailServer.Smtp.Tests;

public sealed class SmtpCommandTests
{
    [Theory]
    [InlineData("EHLO mail.example.com", SmtpVerb.Ehlo, "mail.example.com")]
    [InlineData("HELO legacy.example.com", SmtpVerb.Helo, "legacy.example.com")]
    [InlineData("DATA", SmtpVerb.Data, "")]
    [InlineData("RSET", SmtpVerb.Rset, "")]
    [InlineData("NOOP", SmtpVerb.Noop, "")]
    [InlineData("QUIT", SmtpVerb.Quit, "")]
    [InlineData("STARTTLS", SmtpVerb.StartTls, "")]
    [InlineData("AUTH PLAIN dGVzdA==", SmtpVerb.Auth, "PLAIN dGVzdA==")]
    [InlineData("VRFY someone", SmtpVerb.Vrfy, "someone")]
    [InlineData("EXPN staff", SmtpVerb.Expn, "staff")]
    [InlineData("HELP", SmtpVerb.Help, "")]
    public void Verbs_are_recognised(string line, SmtpVerb expected, string argument)
    {
        SmtpCommand command = SmtpCommand.Parse(line);

        command.Verb.ShouldBe(expected);
        command.Argument.ShouldBe(argument);
    }

    [Theory]
    [InlineData("ehlo mail.example.com")]
    [InlineData("Ehlo mail.example.com")]
    [InlineData("eHlO mail.example.com")]
    public void Verbs_are_case_insensitive(string line)
    {
        // RFC 5321 §2.4: verbs are case-insensitive. Clients in the wild use every casing.
        SmtpCommand.Parse(line).Verb.ShouldBe(SmtpVerb.Ehlo);
    }

    [Theory]
    [InlineData("MAIL FROM:<sender@example.com>", SmtpVerb.MailFrom)]
    [InlineData("mail from:<sender@example.com>", SmtpVerb.MailFrom)]
    [InlineData("RCPT TO:<rcpt@example.com>", SmtpVerb.RcptTo)]
    [InlineData("rcpt to:<rcpt@example.com>", SmtpVerb.RcptTo)]
    public void The_two_word_verbs_are_recognised(string line, SmtpVerb expected)
    {
        SmtpCommand.Parse(line).Verb.ShouldBe(expected);
    }

    [Theory]
    [InlineData("MAILFROM:<a@b.example>")]
    [InlineData("MAIL")]
    [InlineData("RCPTTO:<a@b.example>")]
    [InlineData("RCPT")]
    [InlineData("STARTTLSX")]
    [InlineData("EHLOX example.com")]
    [InlineData("XCLIENT NAME=evil")]
    [InlineData("")]
    public void Near_misses_are_not_commands(string line)
    {
        // A parser that matched by prefix would accept every one of these. Accepting a command
        // no specification describes is how a server ends up implementing an attacker's
        // protocol instead of SMTP.
        SmtpCommand.Parse(line).Verb.ShouldBe(SmtpVerb.Unknown);
    }

    [Fact]
    public void The_terminator_is_not_part_of_the_argument()
    {
        SmtpCommand.Parse("EHLO mail.example.com\r\n").Argument.ShouldBe("mail.example.com");
        SmtpCommand.Parse("EHLO mail.example.com\n").Argument.ShouldBe("mail.example.com");
    }

    [Fact]
    public void The_raw_line_is_kept_for_diagnostics()
    {
        SmtpCommand.Parse("WHAT IS THIS\r\n").Raw.ShouldBe("WHAT IS THIS");
    }

    [Fact]
    public void Whitespace_after_the_colon_is_tolerated()
    {
        // RFC 5321 forbids it; several clients emit it anyway. Refusing mail over a space is a
        // worse outcome than a TrimStart.
        SmtpCommand command = SmtpCommand.Parse("MAIL FROM: <sender@example.com>");

        command.Verb.ShouldBe(SmtpVerb.MailFrom);
        SmtpPath.TryParse(command.Argument, out EmailAddress? address, out _).ShouldBeTrue();
        address!.ToString().ShouldBe("sender@example.com");
    }
}

public sealed class SmtpPathTests
{
    [Fact]
    public void An_ordinary_address_parses()
    {
        SmtpPath.TryParse("<user@example.com>", out EmailAddress? address, out IReadOnlyList<string> parameters)
            .ShouldBeTrue();

        address!.ToString().ShouldBe("user@example.com");
        parameters.ShouldBeEmpty();
    }

    [Fact]
    public void The_null_reverse_path_is_legal_and_has_no_address()
    {
        // "<>" is what a bounce uses as its sender, so that a bounce cannot itself bounce. A
        // server that rejected it would break every delivery status notification on the
        // Internet.
        SmtpPath.TryParse("<>", out EmailAddress? address, out _).ShouldBeTrue();

        address.ShouldBeNull();
    }

    [Theory]
    [InlineData("user@example.com")]            // no brackets
    [InlineData("<user@example.com")]           // unterminated
    [InlineData("<not an address>")]            // brackets, but no address inside
    [InlineData("<@relay.example:>")]           // source route with nothing routed to
    [InlineData("<\"unterminated@example.com>")] // quote never closes, so neither does the path
    [InlineData("")]
    [InlineData("   ")]
    public void Malformed_paths_are_refused_without_throwing(string argument)
    {
        // These octets came off the network. An unparseable path earns a 501, not an exception
        // on the session loop.
        SmtpPath.TryParse(argument, out _, out _).ShouldBeFalse();
    }

    [Fact]
    public void A_quoted_local_part_containing_an_angle_bracket_is_not_cut_in_half()
    {
        // Legal per RFC 5321 §4.1.2, and a parser that took the first '>' would truncate the
        // address to nonsense and reject well-formed mail. The address model accepts quoted
        // local-parts, so the path parser has to be able to read them back.
        SmtpPath.TryParse("<\"a>b\"@example.com> SIZE=10",
            out EmailAddress? address, out IReadOnlyList<string> parameters).ShouldBeTrue();

        address.ShouldNotBeNull();
        address.LocalPart.ShouldBe("a>b");
        parameters.ShouldBe(["SIZE=10"]);
    }

    [Fact]
    public void An_escaped_quote_inside_a_quoted_local_part_does_not_end_the_quoting()
    {
        SmtpPath.TryParse("<\"a\\\">b\"@example.com>", out EmailAddress? address, out _)
            .ShouldBeTrue();

        address.ShouldNotBeNull();
        address.LocalPart.ShouldBe("a\\\">b");
    }

    [Fact]
    public void A_source_route_is_stripped_rather_than_honoured()
    {
        // RFC 5321 §F.2 deprecates source routes. Honouring one lets a sender nominate a third
        // party for this server to relay through, which is an open relay with extra steps.
        SmtpPath.TryParse("<@relay.example.net,@other.example:user@example.com>",
            out EmailAddress? address, out _).ShouldBeTrue();

        address!.ToString().ShouldBe("user@example.com");
    }

    [Fact]
    public void Esmtp_parameters_are_separated_from_the_address()
    {
        SmtpPath.TryParse("<user@example.com> SIZE=12345 BODY=8BITMIME",
            out EmailAddress? address, out IReadOnlyList<string> parameters).ShouldBeTrue();

        address!.ToString().ShouldBe("user@example.com");
        parameters.ShouldBe(["SIZE=12345", "BODY=8BITMIME"]);
    }

    [Fact]
    public void The_size_parameter_is_read_when_present()
    {
        SmtpPath.TryParse("<a@b.example> SIZE=4096", out _, out IReadOnlyList<string> parameters);

        SmtpPath.ReadSizeParameter(parameters).ShouldBe(4096L);
    }

    [Theory]
    [InlineData("SIZE=")]
    [InlineData("SIZE=abc")]
    [InlineData("SIZE=-1")]
    [InlineData("SIZE=99999999999999999999999")]
    public void A_malformed_size_parameter_is_ignored_rather_than_trusted(string parameter)
    {
        // SIZE is a sender's claim, and this one is not even a number. Treating it as absent
        // means the real limit is still enforced by counting during DATA.
        SmtpPath.ReadSizeParameter([parameter]).ShouldBeNull();
    }

    [Fact]
    public void A_missing_size_parameter_is_null_not_zero()
    {
        // Zero would mean "the sender promises an empty message" and could wrongly fail a
        // limit check, or wrongly pass one.
        SmtpPath.ReadSizeParameter(["BODY=8BITMIME"]).ShouldBeNull();
    }

    [Fact]
    public void A_unicode_address_survives_the_path_parser()
    {
        // SMTPUTF8. The address model round-trips Unicode and punycode; the path parser must
        // not be the thing that mangles it.
        SmtpPath.TryParse("<postmaster@münchen.example>", out EmailAddress? address, out _)
            .ShouldBeTrue();

        address!.Domain.UnicodeValue.ShouldBe("münchen.example");
    }
}
