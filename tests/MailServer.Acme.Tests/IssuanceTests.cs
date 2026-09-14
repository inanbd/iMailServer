using MailServer.Application;
using MailServer.Application.Abstractions.Acme;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure;
using MailServer.Persistence.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Acme.Tests;

/// <summary>
/// The issuance sequence, end to end against a fake certificate authority.
/// </summary>
/// <remarks>
/// <para>
/// Real SQLite, real migrations, real certificate storage, real bindings, real rate limiter.
/// Only the CA is substituted — see <see cref="FakeAcmeCertificateAuthority"/> for why that is
/// the right seam and what it consequently does not cover.
/// </para>
/// <para>
/// The failure paths get as much attention as the success path, because they are what an
/// operator meets: a certificate that issues first time needs no diagnosis, and a renewal that
/// fails at three in the morning does.
/// </para>
/// </remarks>
public sealed class IssuanceTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "aethermail-acme-tests",
        Guid.NewGuid().ToString("N"));

    private readonly FakeAcmeCertificateAuthority _ca = new();
    private readonly RecordingDnsChallengeProvider _dns = new();
    private readonly ScriptedPreflightCheck _preflight = new();

    private ServiceProvider _services = null!;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_directory);

        IConfiguration configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["MailServer:Server:Hostname"] = "mail.test.example",
                ["MailServer:Storage:DataRoot"] = _directory,
                ["MailServer:Database:Provider"] = "Sqlite",
                ["MailServer:Database:Sqlite:DataSource"] = Path.Combine(_directory, "acme.db"),
                ["MailServer:Security:SecretProtection"] = "Development",

                // Configured as an operator would have to before anything can be issued.
                ["MailServer:Acme:ContactEmail"] = "admin@test.example",
                ["MailServer:Acme:AcceptTermsOfService"] = "true",
                ["MailServer:Acme:Directory"] = "LetsEncryptStaging",
                ["MailServer:Acme:CertificateKeySizeBits"] = "2048",

                // The bootstrap certificate is not wanted here; these tests create their own.
                ["MailServer:Certificates:GenerateSelfSignedOnFirstStart"] = "false",
            })
            .Build();

        ServiceCollection services = new();

        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));
        services.AddApplication();
        services.AddInfrastructure(configuration, isProductionEnvironment: false);
        services.AddSqlitePersistence();

        // The CA, its DNS provider and the pre-flight check. Everything else is real.
        services.AddSingleton<IAcmeClientFactory>(_ca);
        services.AddSingleton<IDnsChallengeProvider>(_dns);
        services.AddSingleton<IAcmePreflightCheck>(_preflight);

        _services = services.BuildServiceProvider();

        await using AsyncServiceScope scope = _services.CreateAsyncScope();
        await scope.ServiceProvider
            .GetRequiredService<IDatabaseMigrator>()
            .MigrateAsync(CancellationToken.None);
    }

    public async Task DisposeAsync()
    {
        await _services.DisposeAsync();

        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

        try
        {
            if (Directory.Exists(_directory))
            {
                Directory.Delete(_directory, recursive: true);
            }
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a test over.
        }
    }

    private async Task<IssuanceResult> IssueAsync(
        AcmeChallengeType challengeType = AcmeChallengeType.Http01,
        params string[] hostnames)
    {
        string[] names = hostnames.Length == 0 ? ["mail.example.com"] : hostnames;

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        return await scope.ServiceProvider
            .GetRequiredService<IAcmeIssuanceService>()
            .IssueAsync(
                [.. names.Select(DomainName.Parse)],
                challengeType,
                bindOnSuccess: true,
                CancellationToken.None);
    }

    // ---- The success path -------------------------------------------------------------------

    [Fact]
    public async Task A_certificate_is_issued_stored_and_bound()
    {
        IssuanceResult result = await IssueAsync();

        result.Succeeded.ShouldBeTrue(result.Failure);
        result.Certificate.ShouldNotBeNull();
        result.Certificate!.Source.ShouldBe(CertificateSource.Acme);

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        ICertificateRepository certificates =
            scope.ServiceProvider.GetRequiredService<ICertificateRepository>();

        Certificate? stored = await certificates
            .GetAsync(result.Certificate.Id, CancellationToken.None);

        stored.ShouldNotBeNull();
        stored.Covers(DomainName.Parse("mail.example.com")).ShouldBeTrue();

        CertificateBinding? binding = await certificates
            .GetBindingByHostnameAsync(DomainName.Parse("mail.example.com"), CancellationToken.None);

        binding.ShouldNotBeNull();
        binding.CertificateId.ShouldBe(result.Certificate.Id);
        binding.IsDefault.ShouldBeTrue("the first binding must be the default");
    }

    [Fact]
    public async Task The_account_is_registered_once_and_reused()
    {
        await IssueAsync();
        await IssueAsync(AcmeChallengeType.Http01, "imap.example.com");

        // Registering again per issuance would be pointless traffic and, on a real CA, would
        // look like an account-creation loop.
        _ca.RegistrationCalls.ShouldBe(1);

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        IReadOnlyList<AcmeAccount> accounts = await scope.ServiceProvider
            .GetRequiredService<IAcmeRepository>()
            .GetAccountsAsync(CancellationToken.None);

        accounts.ShouldHaveSingleItem().IsUsable.ShouldBeTrue();
    }

    [Fact]
    public async Task The_order_is_recorded_as_valid()
    {
        IssuanceResult result = await IssueAsync();

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        AcmeOrder? order = await scope.ServiceProvider
            .GetRequiredService<IAcmeRepository>()
            .GetOrderAsync(result.OrderId, CancellationToken.None);

        order.ShouldNotBeNull();
        order.Status.ShouldBe(AcmeOrderStatus.Valid);
        order.ConsumedCaQuota.ShouldBeTrue();
        order.IssuedCertificateId.ShouldBe(result.Certificate!.Id);
    }

    [Fact]
    public async Task A_multi_hostname_certificate_covers_every_name()
    {
        IssuanceResult result = await IssueAsync(
            AcmeChallengeType.Http01,
            "mail.example.com",
            "imap.example.com",
            "smtp.example.com");

        result.Succeeded.ShouldBeTrue(result.Failure);

        result.Certificate!.SubjectAlternativeNames
            .Select(static n => n.Value)
            .ShouldBe(["mail.example.com", "imap.example.com", "smtp.example.com"], ignoreOrder: true);
    }

    // ---- Challenge handling -----------------------------------------------------------------

    [Fact]
    public async Task An_http_challenge_is_published_and_then_cleaned_up()
    {
        IHttpChallengeStore store = _services.GetRequiredService<IHttpChallengeStore>();

        await IssueAsync();

        _ca.IssuedChallenges.ShouldNotBeEmpty();

        // Cleanup runs in a finally on every path. A leftover token is a hygiene problem and a
        // standing hint about how this domain proves control.
        foreach (AcmeChallenge challenge in _ca.IssuedChallenges)
        {
            store.TryGet(challenge.Token).ShouldBeNull();
        }

        store.Count.ShouldBe(0);
    }

    [Fact]
    public async Task A_dns_challenge_record_is_published_and_then_removed()
    {
        _ca.OfferedChallengeType = AcmeChallengeType.Dns01;

        IssuanceResult result = await IssueAsync(AcmeChallengeType.Dns01);

        result.Succeeded.ShouldBeTrue(result.Failure);

        _dns.Published.ShouldHaveSingleItem().ShouldBe("_acme-challenge.mail.example.com");
        _dns.Removed.ShouldHaveSingleItem().ShouldBe("_acme-challenge.mail.example.com");
    }

    /// <summary>
    /// Cleanup must run when issuance fails too — that is the case where a leftover artefact
    /// would otherwise sit there indefinitely.
    /// </summary>
    [Fact]
    public async Task Challenges_are_cleaned_up_after_a_failure()
    {
        _ca.OfferedChallengeType = AcmeChallengeType.Dns01;
        _ca.ValidationFailure = new AcmeProtocolException("Validation failed.");

        IssuanceResult result = await IssueAsync(AcmeChallengeType.Dns01);

        result.Succeeded.ShouldBeFalse();
        _dns.Removed.ShouldHaveSingleItem().ShouldBe("_acme-challenge.mail.example.com");
    }

    /// <summary>
    /// Manual DNS-01 stops before asking the CA to validate, because asking it to look at a
    /// record the operator has not published spends one of five failed validations per hour.
    /// </summary>
    [Fact]
    public async Task Manual_dns_returns_instructions_without_asking_the_ca_to_validate()
    {
        _ca.OfferedChallengeType = AcmeChallengeType.Dns01;
        _dns.SupportsAutomaticPublication = false;

        IssuanceResult result = await IssueAsync(AcmeChallengeType.Dns01);

        result.Succeeded.ShouldBeFalse();
        result.ManualDnsInstructions.ShouldNotBeNull().ShouldHaveSingleItem()
            .ShouldContain("_acme-challenge.mail.example.com");

        _ca.ValidateCalls.ShouldBe(0);
        _ca.FinalizeCalls.ShouldBe(0);
    }

    // ---- Failure paths ----------------------------------------------------------------------

    [Fact]
    public async Task A_blocking_preflight_finding_stops_the_order_before_the_ca_sees_it()
    {
        _preflight.ShouldBlock = true;
        _preflight.BlockReason = "'mail.example.com' does not resolve to any address.";

        IssuanceResult result = await IssueAsync();

        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldNotBeNull().ShouldContain("does not resolve");

        // The whole point: nothing reached the CA, so no rate-limit slot was spent.
        _ca.CreateOrderCalls.ShouldBe(0);

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        AcmeOrder? order = await scope.ServiceProvider
            .GetRequiredService<IAcmeRepository>()
            .GetOrderAsync(result.OrderId, CancellationToken.None);

        order!.Status.ShouldBe(AcmeOrderStatus.Abandoned);
        order.ConsumedCaQuota.ShouldBeFalse();
    }

    [Fact]
    public async Task A_validation_failure_is_recorded_with_the_ca_explanation()
    {
        _ca.ValidationFailure = new AcmeProtocolException(
            "Invalid response from http://mail.example.com/.well-known/acme-challenge/x: 404",
            "urn:ietf:params:acme:error:unauthorized");

        IssuanceResult result = await IssueAsync();

        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldNotBeNull().ShouldContain("404");

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        AcmeOrder? order = await scope.ServiceProvider
            .GetRequiredService<IAcmeRepository>()
            .GetOrderAsync(result.OrderId, CancellationToken.None);

        order!.Status.ShouldBe(AcmeOrderStatus.Invalid);

        // Invalid, not Abandoned: the CA saw this one, so it consumed a slot and the rate
        // limiter must count it.
        order.ConsumedCaQuota.ShouldBeTrue();
        order.LastError.ShouldNotBeNull().ShouldContain("404");
    }

    /// <summary>
    /// A failed attempt must leave no certificate behind — partly so nothing half-installed is
    /// served, and partly because a stray certificate row would count towards the duplicate
    /// limit.
    /// </summary>
    [Fact]
    public async Task A_failed_issuance_installs_nothing()
    {
        _ca.FinalizeFailure = new AcmeProtocolException("The order could not be finalised.");

        IssuanceResult result = await IssueAsync();

        result.Succeeded.ShouldBeFalse();
        result.Certificate.ShouldBeNull();

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        (await scope.ServiceProvider
            .GetRequiredService<ICertificateRepository>()
            .GetAllAsync(CancellationToken.None))
            .ShouldBeEmpty();
    }

    /// <summary>
    /// The rate limiter counts attempts that reached the CA. Five failures in an hour is the
    /// documented limit, and the sixth must be refused locally rather than spending the slot.
    /// </summary>
    [Fact]
    public async Task Repeated_ca_failures_eventually_stop_new_orders_being_submitted()
    {
        _ca.ValidationFailure = new AcmeProtocolException("Validation failed.");

        for (int i = 0; i < 5; i++)
        {
            await IssueAsync();
        }

        int callsBefore = _ca.CreateOrderCalls;

        IssuanceResult refused = await IssueAsync();

        refused.Succeeded.ShouldBeFalse();
        refused.Failure.ShouldNotBeNull().ShouldContain("last hour");

        // Refused locally: the CA was not asked a sixth time.
        _ca.CreateOrderCalls.ShouldBe(callsBefore);
    }

    [Fact]
    public async Task A_local_refusal_does_not_count_towards_the_rate_limit()
    {
        _preflight.ShouldBlock = true;

        for (int i = 0; i < 10; i++)
        {
            await IssueAsync();
        }

        // Ten local refusals must not have ratcheted the limiter shut against an order that
        // has cost the CA nothing.
        _preflight.ShouldBlock = false;

        IssuanceResult result = await IssueAsync();

        result.Succeeded.ShouldBeTrue(result.Failure);
    }

    [Fact]
    public async Task Issuance_is_refused_when_registration_fails()
    {
        _ca.RegistrationFailure = new AcmeProtocolException(
            "The contact address was rejected.");

        IssuanceResult result = await IssueAsync();

        result.Succeeded.ShouldBeFalse();
        result.Failure.ShouldNotBeNull().ShouldContain("No usable ACME account");
        _ca.CreateOrderCalls.ShouldBe(0);
    }

    // ---- Renewal ------------------------------------------------------------------------------

    /// <summary>
    /// Renewal repoints the existing binding at a new certificate, which is what makes it a
    /// hot swap rather than a reconfiguration.
    /// </summary>
    [Fact]
    public async Task Reissuing_repoints_the_existing_binding()
    {
        IssuanceResult first = await IssueAsync();
        first.Succeeded.ShouldBeTrue(first.Failure);

        IssuanceResult second = await IssueAsync();
        second.Succeeded.ShouldBeTrue(second.Failure);

        second.Certificate!.Id.ShouldNotBe(first.Certificate!.Id);

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        ICertificateRepository certificates =
            scope.ServiceProvider.GetRequiredService<ICertificateRepository>();

        IReadOnlyList<CertificateBinding> bindings =
            await certificates.GetBindingsAsync(CancellationToken.None);

        // One binding, repointed - not a second one competing for the same hostname.
        bindings.ShouldHaveSingleItem().CertificateId.ShouldBe(second.Certificate.Id);
    }

    /// <summary>
    /// The certificate must be recorded as coming from ACME, because that is what makes the
    /// lifecycle service renew it.
    /// </summary>
    /// <remarks>
    /// This started as a test documenting a defect. Issuance originally stored its result
    /// through the operator-import path, which records <c>ImportedPfx</c> — a source the
    /// aggregate refuses to auto-renew, on the entirely correct grounds that this server cannot
    /// reissue someone else's imported certificate. The effect was that every certificate this
    /// server obtained automatically would have expired without a single renewal attempt, while
    /// the renewal loop ran happily and found nothing to do.
    /// </remarks>
    [Fact]
    public async Task An_issued_certificate_is_marked_for_automatic_renewal()
    {
        IssuanceResult result = await IssueAsync();

        result.Certificate!.Source.ShouldBe(CertificateSource.Acme);

        result.Certificate.AutoRenew.ShouldBeTrue(
            "an ACME certificate that does not auto-renew will silently expire");
    }

    /// <summary>
    /// The renewal loop's own filter, asserted against a real issued certificate.
    /// </summary>
    /// <remarks>
    /// The behavioural test above would catch a regression; this states the exact condition
    /// <c>CertificateLifecycleService</c> evaluates, so a change to either side has to face
    /// the other.
    /// </remarks>
    [Fact]
    public async Task An_issued_certificate_satisfies_the_renewal_loop_filter()
    {
        IssuanceResult result = await IssueAsync();

        Certificate certificate = result.Certificate!;

        (certificate.AutoRenew && certificate.Source == CertificateSource.Acme)
            .ShouldBeTrue("otherwise the lifecycle service skips it and it expires");
    }
}
