using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Dns;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Deliverability;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Deliverability;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MailServer.Deliverability.Tests;

public sealed class DeliverabilityReportServiceTests
{
    private static readonly DomainName Domain = DomainName.Parse("example.com");
    private static readonly DateTimeOffset Now = new(2026, 9, 19, 12, 0, 0, TimeSpan.Zero);

    private const long OneHundredGb = 100L * 1024 * 1024 * 1024;

    /// <summary>A resolver that answers everything a well-configured domain would.</summary>
    private static ScriptedDiagnosticsService Resolver() =>
        new ScriptedDiagnosticsService()
            .With("example.com", DnsDiagnosticRecordType.Mx, "10 mail.example.com")
            .With("example.com", DnsDiagnosticRecordType.Txt, "v=spf1 mx -all")
            .With("mail.example.com", DnsDiagnosticRecordType.A, "203.0.113.10")
            .With("_dmarc.example.com", DnsDiagnosticRecordType.Txt,
                "v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
            .With("10.113.0.203.in-addr.arpa", DnsDiagnosticRecordType.Ptr, "mail.example.com");

    private static MailServerOptions Settings(bool smtpEnabled = false)
    {
        MailServerOptions settings = new();

        settings.Server.Hostname = "mail.example.com";
        settings.Server.PublicIpAddress = "203.0.113.10";
        settings.Smtp.InboundMta.Enabled = smtpEnabled;

        return settings;
    }

    /// <summary>Records every relay test the orchestrator asked for.</summary>
    internal sealed class RecordedRelayTests
    {
        public List<(string Host, int Port, string Ehlo)> Calls { get; } = [];

        public bool StartTls { get; set; } = true;

        public Task<OpenRelayResult> RunAsync(
            string host,
            int port,
            string ehlo,
            CancellationToken cancellationToken)
        {
            Calls.Add((host, port, ehlo));

            return Task.FromResult(new OpenRelayResult(true, false, host, [], StartTls));
        }
    }

    private static DeliverabilityReportService Service(
        IDnsDiagnosticsService? resolver = null,
        MailServerOptions? settings = null,
        IReputationProvider? reputationProvider = null,
        RecordedRelayTests? relay = null,
        IDkimKeyRepository? dkim = null,
        IDomainRepository? domainRepository = null,
        ITlsCertificateProvider? tls = null,
        FakeCertificates? certificates = null)
    {
        IDnsDiagnosticsService dns = resolver ?? Resolver();
        MailServerOptions opts = settings ?? Settings();
        ProbeClock clock = new(Now);

        return new DeliverabilityReportService(
            Options.Create(opts),
            new IdentityProbe(dns),
            new AuthenticationProbe(dns),
            new DnsProbe(dns),
            new TransportPolicyProbe(dns, new ScriptedPolicyFetcher(MtaStsFetchOutcome.NotFound)),
            new ReputationProbe(reputationProvider ?? new ScriptedReputationProvider([])),
            new OperationsProbe(
                new ScriptedQueue(new QueueDepth(0, 0, null), new DeliveryOutcomeCounts(100, 1)),
                clock,
                new FixedVolume((OneHundredGb / 2, OneHundredGb)),
                new FixedStore("/var/mail")),
            certificates ?? new FakeCertificates(),
            tls ?? new NoTlsCertificate(),
            dkim ?? new FakeDkimKeys(),
            domainRepository ?? new FakeDomains(),
            clock,
            NullLogger<DeliverabilityReportService>.Instance,
            relay is null ? null : relay.RunAsync);
    }

    // ---------------------------------------------------------------------------------------
    // What a run produces.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A run must leave the certificate the listeners are serving exactly as it found it.
    /// </summary>
    /// <remarks>
    /// The regression this pins was found by running the server rather than by a test: the chain
    /// check wrapped the provider's shared instance in a <c>using</c>, so one readiness report
    /// disposed the certificate every listener presents, and every TLS handshake on every port
    /// failed until the next reload. The provider's contract now says so; this is what holds the
    /// report to it.
    /// </remarks>
    [Fact]
    public async Task A_run_does_not_dispose_the_certificate_the_listeners_are_serving()
    {
        using LiveTlsCertificate tls = new("mail.example.com");

        await Service(tls: tls).RunAsync(Domain, DeliverabilityRunOptions.Full, CancellationToken.None);

        tls.Certificate.Handle.ShouldNotBe(IntPtr.Zero);

        // And it is still usable for what a listener does with it.
        Should.NotThrow(() =>
        {
            using X509Chain chain = new();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.Build(tls.Certificate);
        });
    }

    /// <summary>
    /// The second of two runs reaches the same conclusion about the certificate as the first.
    /// </summary>
    /// <remarks>
    /// The shape the fault had from the outside: the first report was right and every report
    /// after it said the certificate could not be read, because the first had destroyed it.
    /// </remarks>
    [Fact]
    public async Task Consecutive_runs_judge_the_certificate_identically()
    {
        using LiveTlsCertificate tls = new("mail.example.com");

        // Registered as CA-issued, so the trust check has to consult the chain the report built
        // from the live certificate. (A certificate registered as self-signed fails the check on
        // its metadata alone, and the chain would never be looked at.)
        Certificate registered = Certificate.Register(
            CertificateThumbprint.Parse(tls.Certificate.Thumbprint),
            "CN=mail.example.com",
            "CN=Test CA",
            "01",
            [CertificateSubjectName.Parse("mail.example.com")],
            CertificateSource.ImportedPfx,
            CertificateKeyLocation.InWindowsStore(CertificateThumbprint.Parse(tls.Certificate.Thumbprint)),
            Now.AddDays(-10),
            Now.AddDays(80),
            Now);
        CertificateBinding binding = CertificateBinding.Create(
            DomainName.Parse("mail.example.com"), registered.Id, CertificatePurpose.All, isDefault: true, Now);

        DeliverabilityReportService service = Service(tls: tls, certificates: new FakeCertificates(registered, binding));

        DeliverabilityCheck first = (await service.RunAsync(Domain, DeliverabilityRunOptions.Full, CancellationToken.None))
            .Checks.Single(c => c.Id == TlsChecks.CertificateTrustedId);
        DeliverabilityCheck second = (await service.RunAsync(Domain, DeliverabilityRunOptions.Full, CancellationToken.None))
            .Checks.Single(c => c.Id == TlsChecks.CertificateTrustedId);

        // The chain was actually built: a test root is not trusted, so it fails on the chain
        // rather than being unmeasured.
        first.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        first.Evidence!.Found.ShouldBe("chain does not build");

        second.Outcome.ShouldBe(first.Outcome);
        second.Evidence!.Found.ShouldBe(first.Evidence.Found);
    }


    /// <summary>
    /// One run covers every category the report scores.
    /// </summary>
    /// <remarks>
    /// The assertion that keeps the orchestrator honest as categories are added: a report missing
    /// one scores its points as untested, which reads as caution rather than as the omission it
    /// is.
    /// </remarks>
    [Fact]
    public async Task A_run_produces_checks_in_every_category()
    {
        DeliverabilityReport report = await Service().RunAsync(
            Domain,
            DeliverabilityRunOptions.Full,
            CancellationToken.None);

        foreach (DeliverabilityCategory category in Enum.GetValues<DeliverabilityCategory>())
        {
            report.Checks.ShouldContain(c => c.Category == category, category.ToString());
        }
    }

    /// <summary>Every check the report carries has a distinct id.</summary>
    [Fact]
    public async Task Every_check_in_a_run_has_a_distinct_id()
    {
        DeliverabilityReport report = await Service().RunAsync(
            Domain,
            DeliverabilityRunOptions.Full,
            CancellationToken.None);

        report.Checks.Select(c => c.Id).Distinct().Count().ShouldBe(report.Checks.Count);
    }

    /// <summary>The report is stamped with the clock, not with the wall time.</summary>
    [Fact]
    public async Task The_report_is_stamped_from_the_clock()
    {
        DeliverabilityReport report = await Service().RunAsync(
            Domain,
            DeliverabilityRunOptions.Full,
            CancellationToken.None);

        report.ProducedAt.ShouldBe(Now);
    }

    // ---------------------------------------------------------------------------------------
    // The two data dependencies between probes.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// The MX hosts the DNS probe found are what the MTA-STS policy is judged against.
    /// </summary>
    /// <remarks>
    /// Resolving them a second time for the policy check would let the two halves of one report
    /// disagree about what the domain publishes — and the disagreement would show up as a
    /// finding about the policy rather than as the inconsistency it is.
    /// </remarks>
    [Fact]
    public async Task The_mx_hosts_found_by_dns_are_what_the_policy_is_judged_against()
    {
        ScriptedDiagnosticsService dns = Resolver()
            .With("_mta-sts.example.com", DnsDiagnosticRecordType.Txt, "v=STSv1; id=abc");

        DeliverabilityReportService service = new(
            Options.Create(Settings()),
            new IdentityProbe(dns),
            new AuthenticationProbe(dns),
            new DnsProbe(dns),
            new TransportPolicyProbe(
                dns,
                new ScriptedPolicyFetcher(
                    MtaStsFetchOutcome.Fetched,
                    "version: STSv1\nmode: enforce\nmx: somewhere.else.example\nmax_age: 604800")),
            new ReputationProbe(new ScriptedReputationProvider([])),
            new OperationsProbe(
                new ScriptedQueue(new QueueDepth(0, 0, null), new DeliveryOutcomeCounts(100, 1)),
                new ProbeClock(Now),
                new FixedVolume((OneHundredGb / 2, OneHundredGb)),
                new FixedStore("/var/mail")),
            new FakeCertificates(),
            new NoTlsCertificate(),
            new FakeDkimKeys(),
            new FakeDomains(),
            new ProbeClock(Now),
            NullLogger<DeliverabilityReportService>.Instance);

        DeliverabilityReport report = await service.RunAsync(
            Domain,
            DeliverabilityRunOptions.Full,
            CancellationToken.None);

        DeliverabilityCheck policy = report.Checks
            .Single(c => c.Id == TransportPolicyChecks.MtaStsPolicyId);

        policy.Outcome.ShouldBe(DeliverabilityOutcome.Fail);
        policy.Detail.ShouldContain("mail.example.com");
    }

    // ---------------------------------------------------------------------------------------
    // What the run options turn off.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A DNS-only run makes no connection and no third-party query.
    /// </summary>
    /// <remarks>
    /// The checks those would have fed report as not tested, which the score already carries —
    /// and the summary says how many points went unjudged rather than quietly rescaling.
    /// </remarks>
    [Fact]
    public async Task A_dns_only_run_makes_no_connections()
    {
        ScriptedPolicyFetcher fetcher = new();
        ScriptedReputationProvider provider = new(["bl.example.net"]);
        RecordedRelayTests relay = new();

        ScriptedDiagnosticsService dns = Resolver()
            .With("_mta-sts.example.com", DnsDiagnosticRecordType.Txt, "v=STSv1; id=abc");

        DeliverabilityReportService service = new(
            Options.Create(Settings(smtpEnabled: true)),
            new IdentityProbe(dns),
            new AuthenticationProbe(dns),
            new DnsProbe(dns),
            new TransportPolicyProbe(dns, fetcher),
            new ReputationProbe(provider),
            new OperationsProbe(
                new ScriptedQueue(new QueueDepth(0, 0, null), new DeliveryOutcomeCounts(100, 1)),
                new ProbeClock(Now),
                new FixedVolume((OneHundredGb / 2, OneHundredGb)),
                new FixedStore("/var/mail")),
            new FakeCertificates(),
            new NoTlsCertificate(),
            new FakeDkimKeys(),
            new FakeDomains(),
            new ProbeClock(Now),
            NullLogger<DeliverabilityReportService>.Instance,
            relay.RunAsync);

        DeliverabilityReport report = await service.RunAsync(
            Domain,
            DeliverabilityRunOptions.DnsOnly,
            CancellationToken.None);

        fetcher.Calls.ShouldBe(0);
        provider.Asked.ShouldBeEmpty();
        relay.Calls.ShouldBeEmpty();

        report.Checks.ShouldNotContain(c => c.Id == TransportPolicyChecks.MtaStsRecordId);
        report.Checks.ShouldNotContain(c => c.Id == ReputationChecks.IpNotListedId);

        report.Checks
            .Single(c => c.Id == OperationsChecks.NotAnOpenRelayId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>
    /// With no port 25 listener there is nothing to ask, and the relay check says so.
    /// </summary>
    /// <remarks>
    /// Not the same as a clean bill of health: a server whose inbound listener is switched off
    /// has not been shown to refuse relaying, it has been shown not to be listening.
    /// </remarks>
    [Fact]
    public async Task With_no_inbound_listener_the_relay_check_is_unjudged()
    {
        RecordedRelayTests relay = new();

        DeliverabilityReport report = await Service(settings: Settings(smtpEnabled: false), relay: relay)
            .RunAsync(Domain, DeliverabilityRunOptions.Full, CancellationToken.None);

        relay.Calls.ShouldBeEmpty();

        report.Checks
            .Single(c => c.Id == OperationsChecks.NotAnOpenRelayId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);

        report.Checks
            .Single(c => c.Id == TlsChecks.StartTlsOfferedId)
            .Outcome.ShouldBe(DeliverabilityOutcome.Inconclusive);
    }

    /// <summary>
    /// With a listener enabled, the test goes to its port and greets with this server's name.
    /// </summary>
    /// <remarks>
    /// The EHLO name matters: it is what the server sees, and a test that greeted with something
    /// else would be exercising a path no real sender takes.
    /// </remarks>
    [Fact]
    public async Task The_relay_test_goes_to_the_configured_listener()
    {
        MailServerOptions settings = Settings(smtpEnabled: true);
        settings.Smtp.InboundMta.Port = 2525;

        RecordedRelayTests relay = new();

        await Service(settings: settings, relay: relay)
            .RunAsync(Domain, DeliverabilityRunOptions.Full, CancellationToken.None);

        relay.Calls.ShouldHaveSingleItem().ShouldBe(("127.0.0.1", 2525, "mail.example.com"));
    }

    /// <summary>
    /// STARTTLS travels from the relay test's EHLO answer to the TLS check.
    /// </summary>
    /// <remarks>
    /// One connection, two findings. A second probe would open another connection to read a line
    /// this one already has.
    /// </remarks>
    [Theory]
    [InlineData(true, DeliverabilityOutcome.Pass)]
    [InlineData(false, DeliverabilityOutcome.Fail)]
    public async Task Starttls_travels_from_the_relay_test_to_the_tls_check(
        bool offered,
        DeliverabilityOutcome expected)
    {
        RecordedRelayTests relay = new() { StartTls = offered };

        DeliverabilityReport report = await Service(settings: Settings(smtpEnabled: true), relay: relay)
            .RunAsync(Domain, DeliverabilityRunOptions.Full, CancellationToken.None);

        report.Checks
            .Single(c => c.Id == TlsChecks.StartTlsOfferedId)
            .Outcome.ShouldBe(expected);
    }

    /// <summary>
    /// A retired DKIM key is not one of this server's selectors.
    /// </summary>
    /// <remarks>
    /// A retired key's selector may still be published on purpose, so signatures made before the
    /// rotation still verify. Reporting it as a configured selector would make a completed
    /// rotation look like a configuration to fix — and once the grace window ends and the record
    /// is withdrawn, the report would start failing a server that did everything right.
    /// </remarks>
    [Fact]
    public async Task A_retired_dkim_key_is_not_a_configured_selector()
    {
        MailDomain record = MailDomain.Create(DomainId.New(), Domain, Now);
        DomainId domainId = record.Id;

        DkimKey active = DkimKey.Generate(
            domainId, DkimSelector.Parse("current"), DkimKeyAlgorithm.RsaSha256, "AAAA", 2048, Now);

        active.Publish(Now);
        active.Activate(Now);

        DkimKey retired = DkimKey.Generate(
            domainId, DkimSelector.Parse("previous"), DkimKeyAlgorithm.RsaSha256, "BBBB", 2048, Now);

        retired.Publish(Now);
        retired.Activate(Now);
        retired.Retire(TimeSpan.FromDays(7), Now);

        ScriptedDiagnosticsService dns = Resolver();

        DeliverabilityReport report = await Service(
                resolver: dns,
                dkim: new FakeDkimKeys([active, retired]),
                domainRepository: new FakeDomains(record))
            .RunAsync(Domain, DeliverabilityRunOptions.Full, CancellationToken.None);

        dns.Asked.ShouldContain(("current._domainkey.example.com", DnsDiagnosticRecordType.Txt));
        dns.Asked.ShouldNotContain(("previous._domainkey.example.com", DnsDiagnosticRecordType.Txt));

        report.ShouldNotBeNull();
    }

    // ---------------------------------------------------------------------------------------
    // Failure.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// A probe that throws does not take the report with it.
    /// </summary>
    /// <remarks>
    /// An operator with one unreachable nameserver should get the points that were measurable,
    /// not an error page. The categories the failed probes would have fed are absent, which the
    /// score reports as untested — and the summary leads with the real denominator rather than
    /// rescaling a handful of checks to a hundred.
    /// </remarks>
    [Fact]
    public async Task A_probe_that_throws_does_not_take_the_report_with_it()
    {
        DeliverabilityReport report = await Service(resolver: new ThrowingDiagnosticsService())
            .RunAsync(Domain, DeliverabilityRunOptions.Full, CancellationToken.None);

        // The DNS-backed categories are gone; the ones that read this server's own state remain.
        report.Checks.ShouldNotContain(c => c.Category == DeliverabilityCategory.Identity);
        report.Checks.ShouldContain(c => c.Category == DeliverabilityCategory.Operations);

        report.Readiness.ShouldNotBe(DeliverabilityReadiness.Ready);
        report.Summarise().ShouldContain("not tested");
    }

    /// <summary>
    /// Cancellation is not swallowed by the boundary that catches probe failures.
    /// </summary>
    /// <remarks>
    /// The boundary exists so one unreachable nameserver does not cost the whole report. A
    /// cancelled run is not that: the caller asked for it to stop, and turning their cancellation
    /// into "the probe failed, here are ninety points" would hand back a report they no longer
    /// wanted and hide that it was abandoned.
    /// </remarks>
    [Fact]
    public async Task Cancellation_is_not_swallowed_by_the_probe_boundary()
    {
        using CancellationTokenSource cancelling = new();

        DeliverabilityReportService service = Service(
            resolver: new CancellingDiagnosticsService(cancelling));

        await Should.ThrowAsync<OperationCanceledException>(() =>
            service.RunAsync(Domain, DeliverabilityRunOptions.Full, cancelling.Token));
    }

    // ---------------------------------------------------------------------------------------
    // Classifying a chain build.
    // ---------------------------------------------------------------------------------------

    /// <summary>A chain that builds is trusted, whatever else is reported alongside it.</summary>
    [Fact]
    public void A_chain_that_builds_is_trusted()
    {
        DeliverabilityReportService.Classify(true, X509ChainStatusFlags.NoError)
            .ShouldBe(CertificateChainStatus.Trusted);
    }

    /// <summary>
    /// Revocation that could not be determined is not a broken chain.
    /// </summary>
    /// <remarks>
    /// An unreachable CRL or OCSP endpoint fails the build with nothing but these flags. The
    /// chain itself built; only its revocation state is unknown. Reporting it as untrusted would
    /// send an operator to reinstall intermediates that were never missing — and it would happen
    /// to everyone whose outbound network blocks OCSP, which is a great many people.
    /// </remarks>
    [Theory]
    [InlineData(X509ChainStatusFlags.RevocationStatusUnknown)]
    [InlineData(X509ChainStatusFlags.OfflineRevocation)]
    [InlineData(X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation)]
    public void Unknown_revocation_alone_is_not_an_untrusted_chain(X509ChainStatusFlags flags)
    {
        DeliverabilityReportService.Classify(false, flags).ShouldBe(CertificateChainStatus.Trusted);
    }

    /// <summary>
    /// A revoked certificate is revoked, even when the chain is broken as well.
    /// </summary>
    /// <remarks>
    /// The two arrive together often — a revoked intermediate breaks everything below it — and
    /// the revocation is the finding that matters: there is no chain left to repair.
    /// </remarks>
    [Theory]
    [InlineData(X509ChainStatusFlags.Revoked)]
    [InlineData(X509ChainStatusFlags.Revoked | X509ChainStatusFlags.PartialChain)]
    [InlineData(X509ChainStatusFlags.Revoked | X509ChainStatusFlags.UntrustedRoot)]
    public void A_revoked_chain_is_revoked_whatever_else_is_wrong(X509ChainStatusFlags flags)
    {
        DeliverabilityReportService.Classify(false, flags).ShouldBe(CertificateChainStatus.Revoked);
    }

    /// <summary>A genuine chain fault is untrusted, including alongside unknown revocation.</summary>
    [Theory]
    [InlineData(X509ChainStatusFlags.PartialChain)]
    [InlineData(X509ChainStatusFlags.UntrustedRoot)]
    [InlineData(X509ChainStatusFlags.NotTimeValid)]
    [InlineData(X509ChainStatusFlags.PartialChain | X509ChainStatusFlags.RevocationStatusUnknown)]
    public void A_real_chain_fault_is_untrusted(X509ChainStatusFlags flags)
    {
        DeliverabilityReportService.Classify(false, flags).ShouldBe(CertificateChainStatus.Untrusted);
    }

    // ---------------------------------------------------------------------------------------
    // The CAA issuer.
    // ---------------------------------------------------------------------------------------

    /// <summary>
    /// An ACME directory maps to the CA's own domain, and an unknown one maps to nothing.
    /// </summary>
    /// <remarks>
    /// A CAA <c>issue</c> value names the issuer's domain, which is not derivable from a
    /// directory URL: Let's Encrypt serves from <c>acme-v02.api.letsencrypt.org</c> and is
    /// authorised as <c>letsencrypt.org</c>. Guessing for a custom directory would invent a
    /// finding, so it maps to null and the check goes unjudged.
    /// </remarks>
    [Theory]
    [InlineData(AcmeDirectory.LetsEncryptProduction, "letsencrypt.org")]
    [InlineData(AcmeDirectory.LetsEncryptStaging, "letsencrypt.org")]
    [InlineData(AcmeDirectory.Custom, null)]
    public void The_acme_directory_maps_to_the_issuers_own_domain(
        AcmeDirectory directory,
        string? expected)
    {
        DeliverabilityReportService.IssuerDomainFor(directory).ShouldBe(expected);
    }
}
