using MailServer.Application.Abstractions.Dns;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Domain.Smtp;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Smtp;
using MailServer.Infrastructure.Spf;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Smtp.Tests;

/// <summary>
/// <see cref="SmtpCommandProcessor"/>'s SPF wiring at <c>MAIL FROM</c>: which listener it runs
/// for, how a null reverse path falls back to the greeting name, that only <c>TempError</c>
/// refuses the command, and that the outcome ends up on the session for a later DMARC step to
/// read. SPF's own evaluation algorithm is <c>MailServer.Authentication.Tests</c>' job.
/// </summary>
public sealed class SmtpCommandProcessorSpfTests
{
    private const long SizeLimit = 36_700_160;

    private readonly FakeSmtpDirectory _directory = new();

    private sealed class FakeSpfTxtResolver : ITxtRecordResolver
    {
        private readonly Dictionary<string, TxtLookupResult> _results = new(StringComparer.OrdinalIgnoreCase);

        public void SetRecord(string domain, string record) =>
            _results[domain] = TxtLookupResult.Success([record]);

        public void SetTemporaryFailure(string domain) =>
            _results[domain] = TxtLookupResult.Temporary("simulated failure");

        public Task<TxtLookupResult> GetTxtRecordsAsync(string domain, CancellationToken cancellationToken) =>
            Task.FromResult(_results.GetValueOrDefault(domain, TxtLookupResult.Success([])));
    }

    private (SmtpCommandProcessor Processor, FakeSpfTxtResolver Txt) CreateProcessor(
        SmtpListenerRole role = SmtpListenerRole.InboundMta, string remoteAddress = "203.0.113.10")
    {
        var txt = new FakeSpfTxtResolver();

        var dns = new NoOpDnsResolver();
        var evaluator = new SpfEvaluator(txt, dns, NullLogger<SpfEvaluator>.Instance);

        SmtpSessionContext session = new(
            role,
            IpAddressValue.Parse(remoteAddress),
            new DateTimeOffset(2026, 3, 1, 9, 0, 0, TimeSpan.Zero),
            isTlsActive: false);

        SmtpProcessorOptions options = new("mail.example.com", "AetherMail", 100, SizeLimit);

        SmtpCommandProcessor processor = new(
            session, options, _directory, new RelayPolicy(), NullLogger.Instance, spfEvaluator: evaluator);

        return (processor, txt);
    }

    private static async Task<SmtpReply> SendAsync(SmtpCommandProcessor processor, string line) =>
        (await processor.ExecuteAsync(SmtpCommand.Parse(line), default)).Reply;

    [Fact]
    public async Task A_passing_sender_is_recorded_on_the_session()
    {
        (SmtpCommandProcessor processor, FakeSpfTxtResolver txt) = CreateProcessor();
        txt.SetRecord("example.net", "v=spf1 ip4:203.0.113.0/24 -all");

        await SendAsync(processor, "EHLO relay.example.net");
        SmtpReply reply = await SendAsync(processor, "MAIL FROM:<sender@example.net>");

        reply.Code.ShouldBe(250);
        processor.Session.SpfOutcome.ShouldNotBeNull();
        processor.Session.SpfOutcome.Result.ShouldBe(SpfResult.Pass);
        processor.Session.SpfOutcome.CheckedDomain.ShouldBe(DomainName.Parse("example.net"));
    }

    [Fact]
    public async Task A_failing_sender_is_recorded_but_still_accepted_at_mail_from()
    {
        // SPF alone never rejects at MAIL FROM - only DMARC alignment (a later step) acts on it.
        (SmtpCommandProcessor processor, FakeSpfTxtResolver txt) = CreateProcessor();
        txt.SetRecord("example.net", "v=spf1 -all");

        await SendAsync(processor, "EHLO relay.example.net");
        SmtpReply reply = await SendAsync(processor, "MAIL FROM:<sender@example.net>");

        reply.Code.ShouldBe(250);
        processor.Session.SpfOutcome!.Result.ShouldBe(SpfResult.Fail);
    }

    [Fact]
    public async Task A_temporary_dns_failure_refuses_the_command_with_451()
    {
        (SmtpCommandProcessor processor, FakeSpfTxtResolver txt) = CreateProcessor();
        txt.SetTemporaryFailure("example.net");

        await SendAsync(processor, "EHLO relay.example.net");
        SmtpReply reply = await SendAsync(processor, "MAIL FROM:<sender@example.net>");

        reply.Code.ShouldBe(451);
        processor.Session.HasTransaction.ShouldBeFalse();
    }

    [Fact]
    public async Task A_null_reverse_path_falls_back_to_the_helo_domain()
    {
        (SmtpCommandProcessor processor, FakeSpfTxtResolver txt) = CreateProcessor();
        txt.SetRecord("relay.example.net", "v=spf1 ip4:203.0.113.0/24 -all");

        await SendAsync(processor, "EHLO relay.example.net");
        SmtpReply reply = await SendAsync(processor, "MAIL FROM:<>");

        reply.Code.ShouldBe(250);
        processor.Session.SpfOutcome!.Result.ShouldBe(SpfResult.Pass);
        processor.Session.SpfOutcome.CheckedDomain.ShouldBe(DomainName.Parse("relay.example.net"));
    }

    [Fact]
    public async Task Spf_is_never_evaluated_for_a_submission_session()
    {
        // Submission requires authentication before MAIL FROM, which this test does not do -
        // the point here is only that whatever refuses the command, it is not SPF: a temporary
        // DNS failure set up below would produce a distinctive 451 if SPF ran at all.
        (SmtpCommandProcessor processor, FakeSpfTxtResolver txt) = CreateProcessor(SmtpListenerRole.Submission);
        txt.SetTemporaryFailure("example.net");

        await SendAsync(processor, "EHLO client.example.net");
        SmtpReply reply = await SendAsync(processor, "MAIL FROM:<sender@example.net>");

        reply.Code.ShouldNotBe(451);
        processor.Session.SpfOutcome.ShouldBeNull();
    }

    [Fact]
    public async Task The_outcome_is_cleared_between_transactions()
    {
        (SmtpCommandProcessor processor, FakeSpfTxtResolver txt) = CreateProcessor();
        txt.SetRecord("example.net", "v=spf1 ip4:203.0.113.0/24 -all");

        await SendAsync(processor, "EHLO relay.example.net");
        await SendAsync(processor, "MAIL FROM:<sender@example.net>");
        processor.Session.SpfOutcome.ShouldNotBeNull();

        await SendAsync(processor, "RSET");

        processor.Session.SpfOutcome.ShouldBeNull();
    }
}
