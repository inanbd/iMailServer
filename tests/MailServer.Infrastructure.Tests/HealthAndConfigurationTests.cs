using MailServer.Application.Abstractions.Monitoring;
using MailServer.Domain.Enums;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Monitoring;
using MailServer.Infrastructure.Time;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Tests;

public sealed class HealthRegistryTests
{
    private static HealthRegistry CreateRegistry() => new(new SystemClock());

    [Fact]
    public void A_registry_with_no_readings_reports_unknown()
    {
        // Not Healthy. Claiming health before anything has reported would show a green light
        // on a server that has not started its listeners yet.
        CreateRegistry().GetOverallState().ShouldBe(HealthState.Unknown);
    }

    [Fact]
    public void The_latest_reading_replaces_the_previous_one_for_a_component()
    {
        HealthRegistry registry = CreateRegistry();

        registry.Publish("Smtp", HealthState.Critical, "down");
        registry.Publish("Smtp", HealthState.Healthy, "recovered");

        registry.GetAll().ShouldHaveSingleItem().State.ShouldBe(HealthState.Healthy);
        registry.Get("Smtp")!.Message.ShouldBe("recovered");
    }

    [Fact]
    public void Critical_dominates_every_other_state()
    {
        HealthRegistry registry = CreateRegistry();

        registry.Publish("A", HealthState.Healthy, "fine");
        registry.Publish("B", HealthState.Warning, "degraded");
        registry.Publish("C", HealthState.Critical, "broken");

        registry.GetOverallState().ShouldBe(HealthState.Critical);
    }

    [Fact]
    public void Warning_outranks_unknown()
    {
        // A confirmed degradation is more actionable than "we could not determine this".
        HealthRegistry registry = CreateRegistry();

        registry.Publish("A", HealthState.Unknown, "not evaluated");
        registry.Publish("B", HealthState.Warning, "degraded");

        registry.GetOverallState().ShouldBe(HealthState.Warning);
    }

    [Fact]
    public void Unknown_outranks_healthy()
    {
        HealthRegistry registry = CreateRegistry();

        registry.Publish("A", HealthState.Healthy, "fine");
        registry.Publish("B", HealthState.Unknown, "not evaluated");

        registry.GetOverallState().ShouldBe(HealthState.Unknown);
    }

    [Fact]
    public void All_healthy_reports_healthy()
    {
        HealthRegistry registry = CreateRegistry();

        registry.Publish("A", HealthState.Healthy, "fine");
        registry.Publish("B", HealthState.Healthy, "fine");

        registry.GetOverallState().ShouldBe(HealthState.Healthy);
    }

    [Fact]
    public void Component_names_are_matched_case_insensitively()
    {
        HealthRegistry registry = CreateRegistry();

        registry.Publish("SmtpInbound", HealthState.Healthy, "running");

        registry.Get("smtpinbound").ShouldNotBeNull();
    }

    [Fact]
    public void An_unreported_component_reads_as_null() =>
        CreateRegistry().Get("NeverReported").ShouldBeNull();

    [Fact]
    public async Task Concurrent_publishers_do_not_corrupt_the_registry()
    {
        // The publish path must never block: it runs on the SMTP accept path, and a health
        // system able to stall mail flow would be a liability rather than an asset.
        HealthRegistry registry = CreateRegistry();

        Task[] publishers = new Task[16];

        for (int i = 0; i < publishers.Length; i++)
        {
            int index = i;

            publishers[i] = Task.Run(() =>
            {
                for (int j = 0; j < 200; j++)
                {
                    registry.Publish($"Component{index}", HealthState.Healthy, $"tick {j}");
                }
            });
        }

        await Task.WhenAll(publishers);

        registry.GetAll().Count.ShouldBe(16);
        registry.GetOverallState().ShouldBe(HealthState.Healthy);
    }

    [Fact]
    public void A_reading_can_carry_structured_detail()
    {
        HealthRegistry registry = CreateRegistry();

        registry.Publish(new HealthReading(
            "Disk",
            HealthState.Warning,
            "low",
            DateTimeOffset.UtcNow,
            new Dictionary<string, string>(StringComparer.Ordinal) { ["FreeBytes"] = "1024" }));

        registry.Get("Disk")!.Data!["FreeBytes"].ShouldBe("1024");
    }
}

public sealed class MailServerOptionsValidatorTests
{
    private static MailServerOptions ValidOptions() => new()
    {
        Server = new ServerOptions { Hostname = "mail.example.com" },
        Database = new DatabaseOptions
        {
            Provider = DatabaseProvider.Sqlite,
            Sqlite = new SqliteOptions { DataSource = "Data/mail.db", JournalMode = "WAL" },
        },
        Storage = new StorageOptions { DataRoot = "Data", MaxMessageSizeBytes = 35L * 1024 * 1024 },
        Security = new SecurityOptions
        {
            SecretProtection = System.OperatingSystem.IsWindows()
                ? SecretProtectionScheme.Dpapi
                : SecretProtectionScheme.Development,
        },
        Ipc = new IpcOptions { PipeName = "AetherMail.Admin" },
        Maintenance = new MaintenanceOptions { Mode = "Normal" },
    };

    [Fact]
    public void A_valid_development_configuration_passes()
    {
        MailServerOptionsValidator validator = new(isProductionEnvironment: false);

        validator.Validate(null, ValidOptions()).Succeeded.ShouldBeTrue();
    }

    [Theory]
    [InlineData("")]
    [InlineData("localhost")]
    [InlineData("not a hostname")]
    [InlineData("-bad.example.com")]
    public void An_invalid_server_hostname_fails(string hostname)
    {
        // The hostname is announced in EHLO and must match the PTR record for the sending IP.
        // A server running with a wrong one sends mail that fails reverse-DNS checks
        // everywhere, which is far worse than refusing to start.
        MailServerOptions options = ValidOptions();
        options.Server.Hostname = hostname;

        MailServerOptionsValidator validator = new(isProductionEnvironment: false);

        validator.Validate(null, options).Failed.ShouldBeTrue();
    }

    [Fact]
    public void An_invalid_public_ip_address_fails()
    {
        MailServerOptions options = ValidOptions();
        options.Server.PublicIpAddress = "999.999.999.999";

        new MailServerOptionsValidator(isProductionEnvironment: false)
            .Validate(null, options).Failed.ShouldBeTrue();
    }

    [Fact]
    public void A_valid_public_ip_address_passes()
    {
        MailServerOptions options = ValidOptions();
        options.Server.PublicIpAddress = "203.0.113.10";

        new MailServerOptionsValidator(isProductionEnvironment: false)
            .Validate(null, options).Succeeded.ShouldBeTrue();
    }

    [Fact]
    public void A_non_wal_journal_mode_is_flagged()
    {
        // WAL is required for acceptable concurrency between IMAP readers and the queue
        // writer. Deviating should be a deliberate, visible choice.
        MailServerOptions options = ValidOptions();
        options.Database.Sqlite.JournalMode = "DELETE";

        new MailServerOptionsValidator(isProductionEnvironment: false)
            .Validate(null, options).Failed.ShouldBeTrue();
    }

    [Fact]
    public void The_development_secret_protector_is_refused_in_production()
    {
        // Rule 105: no insecure fallbacks. The development protector keeps its key on disk
        // beside the data it protects and must never guard DKIM or ACME keys in production.
        MailServerOptions options = ValidOptions();
        options.Security.SecretProtection = SecretProtectionScheme.Development;

        MailServerOptionsValidator validator = new(isProductionEnvironment: true);

        ValidateOptionsResult result = validator.Validate(null, options);

        result.Failed.ShouldBeTrue();
        result.Failures.ShouldNotBeNull();
        result.Failures.ShouldContain(
            f => f.Contains("SecretProtection", StringComparison.Ordinal) &&
                 f.Contains("Dpapi", StringComparison.Ordinal),
            "the failure must name the setting and the remedy, not merely report a problem");
    }

    [Fact]
    public void An_inline_sql_connection_string_is_refused_in_production()
    {
        MailServerOptions options = ValidOptions();
        options.Database.Provider = DatabaseProvider.SqlServer;
        options.Database.SqlServer.ConnectionString = "Server=.;Database=mail;User Id=sa;Password=x";
        options.Security.SecretProtection = SecretProtectionScheme.Dpapi;

        MailServerOptionsValidator validator = new(isProductionEnvironment: true);

        // A credential in a JSON file ends up in support tickets and source control.
        validator.Validate(null, options).Failed.ShouldBeTrue();
    }

    [Fact]
    public void Sql_server_with_neither_a_connection_string_nor_a_secret_name_fails()
    {
        MailServerOptions options = ValidOptions();
        options.Database.Provider = DatabaseProvider.SqlServer;

        new MailServerOptionsValidator(isProductionEnvironment: false)
            .Validate(null, options).Failed.ShouldBeTrue();
    }

    [Theory]
    [InlineData("")]
    [InlineData("has\\backslash")]
    [InlineData("has/slash")]
    public void An_invalid_pipe_name_fails(string pipeName)
    {
        // A path separator in the name would escape the pipe namespace.
        MailServerOptions options = ValidOptions();
        options.Ipc.PipeName = pipeName;

        new MailServerOptionsValidator(isProductionEnvironment: false)
            .Validate(null, options).Failed.ShouldBeTrue();
    }

    [Fact]
    public void An_unrecognised_maintenance_mode_fails_with_the_valid_values_listed()
    {
        MailServerOptions options = ValidOptions();
        options.Maintenance.Mode = "Whatever";

        ValidateOptionsResult result =
            new MailServerOptionsValidator(isProductionEnvironment: false).Validate(null, options);

        result.Failed.ShouldBeTrue();
        result.Failures.ShouldNotBeNull();
        result.Failures.ShouldContain(f => f.Contains("Normal", StringComparison.Ordinal));
    }

    [Fact]
    public void Several_problems_are_all_reported_at_once()
    {
        // One at a time turns configuring a server into a guessing game.
        MailServerOptions options = ValidOptions();
        options.Server.Hostname = "localhost";
        options.Ipc.PipeName = string.Empty;
        options.Maintenance.Mode = "Nonsense";

        ValidateOptionsResult result =
            new MailServerOptionsValidator(isProductionEnvironment: false).Validate(null, options);

        result.Failures.ShouldNotBeNull();
        result.Failures.Count().ShouldBeGreaterThanOrEqualTo(3);
    }
}
