using System.Security.Cryptography.X509Certificates;
using MailServer.Application;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure;
using MailServer.Persistence.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Certificates.Tests;

/// <summary>
/// Generation, storage, binding and hot reload, end to end against a real SQLite database.
/// </summary>
/// <remarks>
/// <para>
/// Real migrations, real repositories, real certificate generation, real PKCS#12 files on
/// disk. The only substitution is the clock.
/// </para>
/// <para>
/// Milestone 3's second stated exit criterion is "hot-swap without restart", and it can only
/// be demonstrated against the real provider: the property is that a handshake in progress
/// keeps the certificate it started with while new ones get the replacement, and a fake
/// provider would prove nothing about that.
/// </para>
/// </remarks>
public sealed class CertificateLifecycleTests : IAsyncLifetime
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        "aethermail-certificate-tests",
        Guid.NewGuid().ToString("N"));

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
                ["MailServer:Database:Sqlite:DataSource"] = Path.Combine(_directory, "certs.db"),
                ["MailServer:Security:SecretProtection"] = "Development",

                // The smallest supported key, because these tests generate many certificates
                // and the properties under test are independent of key size. The production
                // default is asserted separately.
                ["MailServer:Certificates:SelfSignedKeySizeBits"] = "2048",
            })
            .Build();

        ServiceCollection services = new();

        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));
        services.AddApplication();
        services.AddInfrastructure(configuration, isProductionEnvironment: false);
        services.AddSqlitePersistence();

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

    private async Task<Certificate> GenerateAsync(params string[] hostnames)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        return await scope.ServiceProvider
            .GetRequiredService<ICertificateManager>()
            .GenerateSelfSignedAsync(
                new SelfSignedCertificateRequest(
                    [.. hostnames.Select(DomainName.Parse)],
                    2048,
                    1),
                CancellationToken.None);
    }

    private async Task BindAsync(
        Certificate certificate,
        string hostname,
        bool isDefault,
        CertificatePurpose purpose = CertificatePurpose.All)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        ICertificateRepository repository =
            scope.ServiceProvider.GetRequiredService<ICertificateRepository>();

        IClock clock = scope.ServiceProvider.GetRequiredService<IClock>();

        CertificateBinding? existing = await repository.GetBindingByHostnameAsync(
            DomainName.Parse(hostname),
            CancellationToken.None);

        if (existing is not null)
        {
            existing.PointAt(certificate.Id, clock.UtcNow);
            await repository.UpdateBindingAsync(existing, CancellationToken.None);
            return;
        }

        CertificateBinding binding = CertificateBinding.Create(
            DomainName.Parse(hostname),
            certificate.Id,
            purpose,
            isDefault,
            clock.UtcNow);

        // Clear BEFORE inserting, matching the production helper. The unique filtered index
        // rejects a second default outright, so the other order fails at the insert.
        if (isDefault)
        {
            await repository.ClearOtherDefaultsAsync(binding.Id, CancellationToken.None);
        }

        await repository.AddBindingAsync(binding, CancellationToken.None);
    }

    private ITlsCertificateProvider Provider =>
        _services.GetRequiredService<ITlsCertificateProvider>();

    // ---- Storage round trip -------------------------------------------------------------

    [Fact]
    public async Task A_generated_certificate_is_persisted_and_reloadable()
    {
        Certificate generated = await GenerateAsync("mail.example.com");

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        Certificate? loaded = await scope.ServiceProvider
            .GetRequiredService<ICertificateRepository>()
            .GetAsync(generated.Id, CancellationToken.None);

        loaded.ShouldNotBeNull();
        loaded.Thumbprint.ShouldBe(generated.Thumbprint);
        loaded.Source.ShouldBe(CertificateSource.SelfSigned);
        loaded.SubjectAlternativeNames.ShouldHaveSingleItem().Value.ShouldBe("mail.example.com");
    }

    /// <summary>
    /// The stored PKCS#12 must be openable with the passphrase from the secret store, and the
    /// private key must survive the round trip — a certificate that loads without its key
    /// cannot terminate TLS.
    /// </summary>
    [Fact]
    public async Task A_stored_certificate_loads_back_with_its_private_key()
    {
        Certificate generated = await GenerateAsync("mail.example.com");

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        using X509Certificate2? loaded = await scope.ServiceProvider
            .GetRequiredService<ICertificateManager>()
            .LoadAsync(generated.KeyLocation, CancellationToken.None);

        loaded.ShouldNotBeNull();
        loaded.HasPrivateKey.ShouldBeTrue();
        loaded.Thumbprint.ShouldBe(generated.Thumbprint.Value);
    }

    /// <summary>
    /// The file on disk must be ciphertext. A PKCS#12 written without a passphrase would look
    /// identical from the API and expose the private key to anyone who can read the directory.
    /// </summary>
    [Fact]
    public async Task The_stored_file_cannot_be_opened_without_the_passphrase()
    {
        Certificate generated = await GenerateAsync("mail.example.com");

        generated.KeyLocation.RelativeFilePath.ShouldNotBeNull();

        string path = Path.Combine(
            _directory,
            "Certificates",
            generated.KeyLocation.RelativeFilePath);

        File.Exists(path).ShouldBeTrue();

        byte[] bytes = await File.ReadAllBytesAsync(path);

        Should.Throw<System.Security.Cryptography.CryptographicException>(() =>
            X509CertificateLoader.LoadPkcs12(bytes, password: null));
    }

    /// <summary>The location must carry the secret's name, never the secret.</summary>
    [Fact]
    public async Task The_key_location_names_the_passphrase_secret_but_does_not_contain_it()
    {
        Certificate generated = await GenerateAsync("mail.example.com");

        generated.KeyLocation.PassphraseSecretName.ShouldNotBeNullOrWhiteSpace();

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        string? passphrase = await scope.ServiceProvider
            .GetRequiredService<Application.Abstractions.Security.ISecretStore>()
            .GetAsync(generated.KeyLocation.PassphraseSecretName!, CancellationToken.None);

        passphrase.ShouldNotBeNullOrWhiteSpace();

        // The value object's string form is what ends up in a log line if it is ever
        // interpolated, so it must name the secret and nothing more.
        generated.KeyLocation.ToString().ShouldNotContain(passphrase!);
        generated.KeyLocation.ToString().ShouldContain(generated.KeyLocation.PassphraseSecretName!);
    }

    // ---- Hot reload ----------------------------------------------------------------------

    [Fact]
    public async Task A_bound_certificate_is_selected_by_its_hostname()
    {
        Certificate certificate = await GenerateAsync("mail.example.com");
        await BindAsync(certificate, "mail.example.com", isDefault: true);

        await Provider.ReloadAsync(CancellationToken.None);

        using X509Certificate2? selected =
            Provider.Select("mail.example.com", CertificatePurpose.SmtpInbound);

        selected.ShouldNotBeNull();
        selected.Thumbprint.ShouldBe(certificate.Thumbprint.Value);
    }

    /// <summary>
    /// SNI is an extension and older MTAs still connect without it. A null hostname must
    /// therefore be answered with the default certificate — returning nothing would fail the
    /// handshake and lose real inbound mail.
    /// </summary>
    [Fact]
    public async Task A_handshake_without_sni_is_answered_with_the_default()
    {
        Certificate certificate = await GenerateAsync("mail.example.com");
        await BindAsync(certificate, "mail.example.com", isDefault: true);

        await Provider.ReloadAsync(CancellationToken.None);

        using X509Certificate2? selected = Provider.Select(null, CertificatePurpose.SmtpInbound);

        selected.ShouldNotBeNull();
        selected.Thumbprint.ShouldBe(certificate.Thumbprint.Value);
    }

    [Fact]
    public async Task An_unknown_hostname_falls_back_to_the_default()
    {
        Certificate certificate = await GenerateAsync("mail.example.com");
        await BindAsync(certificate, "mail.example.com", isDefault: true);

        await Provider.ReloadAsync(CancellationToken.None);

        using X509Certificate2? selected =
            Provider.Select("something.else.invalid", CertificatePurpose.SmtpInbound);

        // A name mismatch is a warning the remote can choose to accept; no certificate at all
        // is a hard handshake failure. The lesser harm is the right default.
        selected.ShouldNotBeNull();
        selected.Thumbprint.ShouldBe(certificate.Thumbprint.Value);
    }

    [Fact]
    public async Task Each_hostname_gets_its_own_certificate()
    {
        Certificate first = await GenerateAsync("mail.example.com");
        Certificate second = await GenerateAsync("imap.example.com");

        await BindAsync(first, "mail.example.com", isDefault: true);
        await BindAsync(second, "imap.example.com", isDefault: false);

        await Provider.ReloadAsync(CancellationToken.None);

        using X509Certificate2? forMail =
            Provider.Select("mail.example.com", CertificatePurpose.SmtpInbound);
        using X509Certificate2? forImap =
            Provider.Select("imap.example.com", CertificatePurpose.MailboxAccess);

        forMail!.Thumbprint.ShouldBe(first.Thumbprint.Value);
        forImap!.Thumbprint.ShouldBe(second.Thumbprint.Value);
    }

    [Fact]
    public async Task Sni_matching_is_case_insensitive()
    {
        Certificate certificate = await GenerateAsync("mail.example.com");
        await BindAsync(certificate, "mail.example.com", isDefault: true);

        await Provider.ReloadAsync(CancellationToken.None);

        // A client may send any casing; DNS names are case-insensitive, and treating them
        // otherwise would serve the wrong certificate for a correctly-spelled hostname.
        using X509Certificate2? selected =
            Provider.Select("MAIL.EXAMPLE.COM", CertificatePurpose.SmtpInbound);

        selected!.Thumbprint.ShouldBe(certificate.Thumbprint.Value);
    }

    [Fact]
    public async Task A_binding_that_does_not_cover_the_service_falls_back_to_the_default()
    {
        Certificate general = await GenerateAsync("mail.example.com");
        Certificate httpsOnly = await GenerateAsync("web.example.com");

        await BindAsync(general, "mail.example.com", isDefault: true);
        await BindAsync(httpsOnly, "web.example.com", isDefault: false, CertificatePurpose.Https);

        await Provider.ReloadAsync(CancellationToken.None);

        using X509Certificate2? forHttps =
            Provider.Select("web.example.com", CertificatePurpose.Https);
        using X509Certificate2? forSmtp =
            Provider.Select("web.example.com", CertificatePurpose.SmtpInbound);

        forHttps!.Thumbprint.ShouldBe(httpsOnly.Thumbprint.Value);
        forSmtp!.Thumbprint.ShouldBe(general.Thumbprint.Value);
    }

    /// <summary>
    /// <b>Milestone 3's exit criterion.</b> Renewal repoints a binding and reloads; new
    /// handshakes get the replacement, and nothing restarted.
    /// </summary>
    [Fact]
    public async Task A_renewed_certificate_takes_effect_without_a_restart()
    {
        Certificate original = await GenerateAsync("mail.example.com");
        await BindAsync(original, "mail.example.com", isDefault: true);

        await Provider.ReloadAsync(CancellationToken.None);

        using (X509Certificate2? before =
               Provider.Select("mail.example.com", CertificatePurpose.SmtpInbound))
        {
            before!.Thumbprint.ShouldBe(original.Thumbprint.Value);
        }

        // The replacement: a new certificate, the same binding repointed at it.
        Certificate replacement = await GenerateAsync("mail.example.com");
        await BindAsync(replacement, "mail.example.com", isDefault: true);

        await Provider.ReloadAsync(CancellationToken.None);

        using X509Certificate2? after =
            Provider.Select("mail.example.com", CertificatePurpose.SmtpInbound);

        after!.Thumbprint.ShouldBe(replacement.Thumbprint.Value);
        after.Thumbprint.ShouldNotBe(original.Thumbprint.Value);
    }

    /// <summary>
    /// The rollback window: a caller that read a certificate before the swap must still be
    /// able to use it afterwards.
    /// </summary>
    /// <remarks>
    /// Disposing the superseded snapshot immediately would throw <c>ObjectDisposedException</c>
    /// inside the TLS stack for any handshake that read the old reference microseconds before
    /// the swap — an intermittent TLS failure with no obvious cause.
    /// </remarks>
    [Fact]
    public async Task A_certificate_read_before_a_reload_remains_usable_after_it()
    {
        Certificate original = await GenerateAsync("mail.example.com");
        await BindAsync(original, "mail.example.com", isDefault: true);

        await Provider.ReloadAsync(CancellationToken.None);

        // Held across the reload, exactly as an in-flight handshake would hold it.
        X509Certificate2? inFlight =
            Provider.Select("mail.example.com", CertificatePurpose.SmtpInbound);

        inFlight.ShouldNotBeNull();

        Certificate replacement = await GenerateAsync("mail.example.com");
        await BindAsync(replacement, "mail.example.com", isDefault: true);

        await Provider.ReloadAsync(CancellationToken.None);

        // Still readable. Touching the thumbprint is enough to prove the object was not
        // disposed out from under the caller.
        Should.NotThrow(() => _ = inFlight.Thumbprint);
        inFlight.Thumbprint.ShouldBe(original.Thumbprint.Value);
    }

    [Fact]
    public async Task A_provider_with_no_bindings_selects_nothing_and_reports_not_ready()
    {
        await Provider.ReloadAsync(CancellationToken.None);

        Provider.IsReady.ShouldBeFalse();
        Provider.Select("mail.example.com", CertificatePurpose.SmtpInbound).ShouldBeNull();
        Provider.Select(null, CertificatePurpose.SmtpInbound).ShouldBeNull();
    }

    [Fact]
    public async Task The_provider_reports_the_hostnames_it_serves()
    {
        Certificate first = await GenerateAsync("mail.example.com");
        Certificate second = await GenerateAsync("imap.example.com");

        await BindAsync(first, "mail.example.com", isDefault: true);
        await BindAsync(second, "imap.example.com", isDefault: false);

        await Provider.ReloadAsync(CancellationToken.None);

        Provider.IsReady.ShouldBeTrue();
        Provider.ConfiguredHostnames
            .Select(static h => h.Value)
            .ShouldBe(["mail.example.com", "imap.example.com"], ignoreOrder: true);
    }

    // ---- Persistence invariants -------------------------------------------------------------

    [Fact]
    public async Task A_second_binding_for_the_same_hostname_is_refused_by_the_database()
    {
        Certificate first = await GenerateAsync("mail.example.com");
        Certificate second = await GenerateAsync("mail.example.com");

        await BindAsync(first, "mail.example.com", isDefault: true);

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        ICertificateRepository repository =
            scope.ServiceProvider.GetRequiredService<ICertificateRepository>();

        // Two bindings for one hostname would make the certificate presented depend on row
        // order, and a TLS configuration that varies between restarts is not diagnosable.
        await Should.ThrowAsync<Exception>(() => repository.AddBindingAsync(
            CertificateBinding.Create(
                DomainName.Parse("mail.example.com"),
                second.Id,
                CertificatePurpose.All,
                isDefault: false,
                DateTimeOffset.UtcNow),
            CancellationToken.None));
    }

    [Fact]
    public async Task Only_one_binding_can_be_the_default()
    {
        Certificate first = await GenerateAsync("mail.example.com");
        Certificate second = await GenerateAsync("imap.example.com");

        await BindAsync(first, "mail.example.com", isDefault: true);
        await BindAsync(second, "imap.example.com", isDefault: true);

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        IReadOnlyList<CertificateBinding> bindings = await scope.ServiceProvider
            .GetRequiredService<ICertificateRepository>()
            .GetBindingsAsync(CancellationToken.None);

        bindings.Count(static b => b.IsDefault).ShouldBe(1);
    }

    [Fact]
    public async Task A_certificate_that_is_still_bound_cannot_be_deleted()
    {
        Certificate certificate = await GenerateAsync("mail.example.com");
        await BindAsync(certificate, "mail.example.com", isDefault: true);

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        // Cascading the delete would silently remove the binding and leave the hostname with
        // no certificate, discovered at the next handshake.
        await Should.ThrowAsync<Exception>(() => scope.ServiceProvider
            .GetRequiredService<ICertificateRepository>()
            .RemoveAsync(certificate.Id, CancellationToken.None));
    }

    [Fact]
    public async Task Deleting_a_certificate_removes_its_file_and_its_passphrase_secret()
    {
        Certificate certificate = await GenerateAsync("mail.example.com");

        string path = Path.Combine(
            _directory,
            "Certificates",
            certificate.KeyLocation.RelativeFilePath!);

        File.Exists(path).ShouldBeTrue();

        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        await scope.ServiceProvider
            .GetRequiredService<ICertificateManager>()
            .RemoveAsync(certificate.KeyLocation, CancellationToken.None);

        File.Exists(path).ShouldBeFalse();

        // The secret must go too. A store accumulating passphrases for certificates that no
        // longer exist is a slow leak of material that is useless but still sensitive.
        (await scope.ServiceProvider
            .GetRequiredService<Application.Abstractions.Security.ISecretStore>()
            .GetAsync(certificate.KeyLocation.PassphraseSecretName!, CancellationToken.None))
            .ShouldBeNull();
    }

    // ---- Health reporting -------------------------------------------------------------------

    /// <summary>
    /// Sends a request through the full pipeline with an authenticated identity assigned.
    /// </summary>
    /// <remarks>
    /// The identity is required, not incidental: <c>AuthorizationBehavior</c> refuses every
    /// non-anonymous request from an unauthenticated scope, which is the Milestone 2 property
    /// these tests must not accidentally bypass. Going through <c>ISender</c> rather than
    /// calling handlers directly is what keeps that enforcement in the path.
    /// </remarks>
    private async Task<TResponse> SendAsync<TResponse>(MediatR.IRequest<TResponse> request)
    {
        await using AsyncServiceScope scope = _services.CreateAsyncScope();

        scope.ServiceProvider
            .GetRequiredService<Application.Abstractions.Security.IAdminContextInitializer>()
            .Assign(
                "Administrator",
                "test-session",
                AdminPermission.FullControl,
                isSystem: false,
                mustChangePassword: false);

        return await scope.ServiceProvider.GetRequiredService<MediatR.ISender>().Send(request);
    }

    private Task<Application.Certificates.Dtos.CertificateHealthDto> GetHealthAsync() =>
        SendAsync(new Application.Certificates.Queries.GetCertificateHealthQuery());

    [Fact]
    public async Task Health_reports_a_server_with_no_certificates()
    {
        Application.Certificates.Dtos.CertificateHealthDto health = await GetHealthAsync();

        health.TotalCertificates.ShouldBe(0);
        health.HasDefaultBinding.ShouldBeFalse();
        health.TlsIsReady.ShouldBeFalse();
        health.SelfSignedWarning.ShouldBeNull();
    }

    /// <summary>
    /// The warning text comes from the server so there is exactly one copy of the wording in
    /// the product. Three hand-typed variants across three views is how a warning quietly
    /// softens into a hint.
    /// </summary>
    [Fact]
    public async Task Health_carries_the_verbatim_self_signed_warning_when_one_is_in_use()
    {
        Certificate certificate = await GenerateAsync("mail.example.com");
        await BindAsync(certificate, "mail.example.com", isDefault: true);

        Application.Certificates.Dtos.CertificateHealthDto health = await GetHealthAsync();

        health.SelfSignedCount.ShouldBe(1);
        health.SelfSignedWarning.ShouldBe(
            Domain.Policies.CertificateRenewalPolicy.SelfSignedWarning);
        health.SelfSignedWarning.ShouldNotBeNull().ShouldContain("NOT PUBLICLY TRUSTED");
    }

    /// <summary>
    /// Surfaced explicitly because its absence is otherwise invisible until a non-SNI MTA
    /// tries to deliver mail and fails — which is reported by the sender, not by this server.
    /// </summary>
    [Fact]
    public async Task Health_reports_a_missing_default_binding()
    {
        Certificate certificate = await GenerateAsync("mail.example.com");
        await BindAsync(certificate, "mail.example.com", isDefault: false);

        Application.Certificates.Dtos.CertificateHealthDto health = await GetHealthAsync();

        health.TotalCertificates.ShouldBe(1);
        health.HasDefaultBinding.ShouldBeFalse();
    }

    [Fact]
    public async Task Health_names_the_hostname_expiring_soonest()
    {
        Certificate certificate = await GenerateAsync("mail.example.com");
        await BindAsync(certificate, "mail.example.com", isDefault: true);

        Application.Certificates.Dtos.CertificateHealthDto health = await GetHealthAsync();

        health.SoonestExpiryHostname.ShouldBe("mail.example.com");

        // One year less the hour of backdating, so a whole-day count of 364 or 365.
        health.SoonestExpiryDays.ShouldNotBeNull();
        health.SoonestExpiryDays!.Value.ShouldBeInRange(360, 366);
    }

    /// <summary>
    /// A self-signed certificate's chain never builds to a trusted root, and reporting
    /// Untrusted is more useful than Healthy for something every client will warn about.
    /// </summary>
    [Fact]
    public async Task A_self_signed_certificate_is_reported_as_untrusted_rather_than_healthy()
    {
        Certificate certificate = await GenerateAsync("mail.example.com");
        await BindAsync(certificate, "mail.example.com", isDefault: true);

        IReadOnlyList<Application.Certificates.Dtos.CertificateDto> certificates =
            await SendAsync(new Application.Certificates.Queries.GetCertificatesQuery());

        Application.Certificates.Dtos.CertificateDto dto = certificates.ShouldHaveSingleItem();

        dto.IsSelfSigned.ShouldBeTrue();
        dto.Status.ShouldBe(CertificateStatus.Untrusted);
    }

    /// <summary>The DTO must carry no path, secret name or key material.</summary>
    [Fact]
    public async Task The_certificate_dto_exposes_no_key_material_or_secret_name()
    {
        Certificate certificate = await GenerateAsync("mail.example.com");

        Application.Certificates.Dtos.CertificateDto dto = await SendAsync(
            new Application.Certificates.Queries.GetCertificateQuery
            {
                CertificateId = certificate.Id.Value,
            });

        string serialised = System.Text.Json.JsonSerializer.Serialize(dto);

        // The DTO crosses the IPC boundary, is rendered, is logged on error and may reach a
        // support bundle. The safest design is one where there is nothing sensitive in it.
        serialised.ShouldNotContain(certificate.KeyLocation.PassphraseSecretName!);
        serialised.ShouldNotContain(certificate.KeyLocation.RelativeFilePath!);
        serialised.ShouldNotContain("PRIVATE KEY");
    }
}
