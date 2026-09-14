using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Infrastructure.Certificates;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Monitoring;
using MailServer.Infrastructure.Persistence;
using MailServer.Infrastructure.Persistence.Queries;
using MailServer.Infrastructure.Persistence.Repositories;
using MailServer.Infrastructure.Platform;
using MailServer.Infrastructure.Security;
using MailServer.Infrastructure.Time;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure;

/// <summary>Registers the Infrastructure layer's implementations of the Application ports.</summary>
public static class DependencyInjection
{
    /// <summary>
    /// Adds configuration binding and validation, platform services, security services,
    /// provider-neutral persistence machinery, and the repositories and query services.
    /// </summary>
    /// <remarks>
    /// The database <b>provider</b> is not registered here. The composition root selects
    /// <c>AddSqlitePersistence()</c> or <c>AddSqlServerPersistence()</c> from configuration,
    /// which is what keeps a provider swap to a single decision in one place.
    /// </remarks>
    public static IServiceCollection AddInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration,
        bool isProductionEnvironment)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        // Dapper's type-handler table is process-global, so it is configured here at
        // registration time rather than lazily at first query. Doing it once, in the one
        // method every host must call, means no code path can reach a query with the
        // handlers unregistered.
        Persistence.DapperConfiguration.Initialize();

        services
            .AddOptions<MailServerOptions>()
            .Bind(configuration.GetSection(MailServerOptions.SectionName))
            .ValidateDataAnnotations()

            // ValidateOnStart turns a configuration mistake into a refusal to start with an
            // actionable message, rather than a mail server that runs and quietly misbehaves.
            .ValidateOnStart();

        services.AddSingleton<IValidateOptions<MailServerOptions>>(
            _ => new MailServerOptionsValidator(isProductionEnvironment));

        // ---- Platform ------------------------------------------------------------------
        services.TryAddSingleton<IClock, SystemClock>();
        services.TryAddSingleton<IEnvironmentInfo, EnvironmentInfo>();
        services.TryAddSingleton<IServerIdentityProvider, ServerIdentityProvider>();
        services.TryAddSingleton<ServerPaths>();
        services.TryAddSingleton<IServerPaths>(sp => sp.GetRequiredService<ServerPaths>());

        // ---- Security ------------------------------------------------------------------
        AddSecretProtection(services, configuration);

        // Scoped, never static: an ambient static correlation id leaks between concurrent
        // sessions and produces log lines that misattribute one session's work to another.
        services.TryAddScoped<CorrelationContext>();
        services.TryAddScoped<ICorrelationContext>(sp => sp.GetRequiredService<CorrelationContext>());

        // Scoped and starting UNAUTHENTICATED with no permissions. If the IPC layer ever
        // fails to authenticate a caller, every request is denied rather than permitted.
        services.TryAddScoped<MutableAdminContext>();
        services.TryAddScoped<IAdminContext>(sp => sp.GetRequiredService<MutableAdminContext>());

        // Read and write are separate interfaces over the same scoped instance: handlers get
        // the read-only IAdminContext, and only the authentication boundary resolves the
        // initializer. One read-write interface would let any handler promote its own
        // permissions.
        services.TryAddScoped<IAdminContextInitializer>(
            sp => sp.GetRequiredService<MutableAdminContext>());

        services.TryAddScoped<IAuditTrail, AuditTrail>();

        // ---- Security: Milestone 2 -----------------------------------------------------
        services.TryAddSingleton<ISecuritySettings, SecuritySettings>();

        // Singleton: the hasher computes its dummy verifier once at construction so that
        // VerifyAgainstDummy costs the same as a real verification without re-hashing a
        // throwaway password on every unauthenticated attempt.
        services.TryAddSingleton<IPasswordHasher, Argon2PasswordHasher>();
        services.TryAddSingleton<IRecoveryKeyGenerator, RecoveryKeyGenerator>();

        // Singleton, and in memory: sessions deliberately do not survive a restart. See
        // AdminSessionManager for why, and why lockout state is persisted instead.
        services.TryAddSingleton<IAdminSessionManager, AdminSessionManager>();

        // Scoped: it reads the ambient correlation id so each event joins the operation
        // that produced it, even though the write itself is out of band.
        services.TryAddScoped<ISecurityEventRecorder, SecurityEventRecorder>();
        services.TryAddScoped<ISecretStore, DatabaseSecretStore>();

        services.TryAddScoped<IAdminAccountRepository, AdminAccountRepository>();
        services.TryAddScoped<ISecurityEventRepository, SecurityEventRepository>();

        services.TryAddScoped<IAuditQueries, AuditQueries>();
        services.TryAddScoped<ISecurityEventQueries, SecurityEventQueries>();

        // ---- Monitoring ----------------------------------------------------------------
        services.TryAddSingleton<IHealthRegistry, HealthRegistry>();
        services.TryAddSingleton<MaintenanceModeAccessor>();
        services.TryAddSingleton<IMaintenanceModeAccessor>(
            sp => sp.GetRequiredService<MaintenanceModeAccessor>());

        // ---- Persistence (provider-neutral) --------------------------------------------
        services.TryAddSingleton<SqlWriteGate>();

        services.TryAddScoped<AmbientDbSession>();
        services.TryAddScoped<IAmbientDbSession>(sp => sp.GetRequiredService<AmbientDbSession>());
        services.TryAddScoped<ITransactionManager, TransactionManager>();

        services.TryAddScoped<IDatabaseMigrator, MigrationRunner>();

        // ---- Certificates (Milestone 3) --------------------------------------------------
        //
        // The TLS provider is a SINGLETON holding the certificate snapshot every handshake
        // reads. Scoping it per request would mean each request built its own snapshot, which
        // defeats the point: the whole design rests on there being exactly one reference for a
        // reload to swap.
        services.TryAddSingleton<ITlsCertificateProvider, TlsCertificateProvider>();

        // Scoped, so two concurrent requests cannot have one's reload satisfy the other's.
        services.TryAddScoped<ITlsReloadCoordinator, TlsReloadCoordinator>();

        services.TryAddScoped<SelfSignedCertificateGenerator>();
        services.TryAddScoped<ProtectedPfxCertificateStore>();
        services.TryAddScoped<CertificateChainValidator>();
        services.TryAddScoped<ICertificateManager, CertificateManager>();
        services.TryAddScoped<ICertificateRepository, CertificateRepository>();

        services.TryAddScoped<IDomainRepository, DomainRepository>();
        services.TryAddScoped<IAuditRepository, AuditRepository>();

        services.TryAddScoped<IDomainQueries, DomainQueries>();
        services.TryAddScoped<IServerStatusQueries, ServerStatusQueries>();

        return services;
    }

    /// <summary>
    /// Selects the secret-protection scheme.
    /// </summary>
    /// <remarks>
    /// <para>
    /// There is deliberately <b>no automatic fallback</b>. If DPAPI is configured on a
    /// non-Windows machine the options validator has already failed the start with an
    /// explanation; quietly substituting the development protector would satisfy brief rule
    /// 105's prohibition on insecure fallbacks in letter but violate it completely in spirit.
    /// </para>
    /// </remarks>
    private static void AddSecretProtection(IServiceCollection services, IConfiguration configuration)
    {
        SecretProtectionScheme scheme = configuration
            .GetSection($"{MailServerOptions.SectionName}:Security:SecretProtection")
            .Get<SecretProtectionScheme?>() ?? SecretProtectionScheme.Dpapi;

        if (scheme == SecretProtectionScheme.Dpapi && OperatingSystem.IsWindows())
        {
            services.TryAddSingleton<ISecretProtector>(sp =>
            {
                // Re-checked inside the factory rather than only at registration time. The
                // platform analyzer cannot see through a deferred lambda, and the second
                // check is genuinely defensive: the factory runs much later than this
                // registration, potentially from a code path that did not exist when the
                // outer guard was written.
                if (!OperatingSystem.IsWindows())
                {
                    throw new PlatformNotSupportedException(
                        "DPAPI secret protection requires Windows. Set " +
                        "MailServer:Security:SecretProtection to 'Development' on other " +
                        "platforms, and keep the environment out of Production.");
                }

                return new DpapiSecretProtector(
                    sp.GetRequiredService<IServerPaths>(),
                    sp.GetRequiredService<ILogger<DpapiSecretProtector>>());
            });

            return;
        }

        services.TryAddSingleton<ISecretProtector, DevelopmentSecretProtector>();
    }
}
