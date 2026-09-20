using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Acme;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Dkim;
using MailServer.Application.Abstractions.Deliverability;
using MailServer.Application.Abstractions.Dns;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Infrastructure.Smtp;
using MailServer.Domain.Policies;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using DnsClient;
using MailServer.Infrastructure.Acme;
using MailServer.Infrastructure.Certificates;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Dkim;
using MailServer.Infrastructure.Dmarc;
using MailServer.Infrastructure.Deliverability;
using MailServer.Infrastructure.Dns;
using MailServer.Infrastructure.Monitoring;
using MailServer.Infrastructure.Smtp.Outbound;
using MailServer.Infrastructure.Persistence;
using MailServer.Infrastructure.Spf;
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

        // ---- ACME (Milestone 4) ------------------------------------------------------------
        //
        // The challenge store is a SINGLETON: the issuance that publishes a token and the
        // Kestrel endpoint that serves it are different call stacks, and a scoped store would
        // mean the endpoint never sees what issuance published.
        services.TryAddSingleton<IHttpChallengeStore, HttpChallengeStore>();

        services.TryAddSingleton<IAcmeSettings, AcmeSettings>();
        services.TryAddSingleton<IAcmeClientFactory, AcmeClientFactory>();
        services.TryAddSingleton<DnsTxtResolver>();

        services.TryAddScoped<AcmeAccountKeyStore>();
        services.TryAddScoped<IDnsChallengeProvider, ManualDnsChallengeProvider>();
        services.TryAddScoped<IAcmePreflightCheck, AcmePreflightCheck>();
        services.TryAddScoped<IAcmeIssuanceService, AcmeIssuanceService>();
        services.TryAddScoped<IAcmeRepository, AcmeRepository>();

        // ---- Mailbox administration (Milestone 5) ------------------------------------------
        services.TryAddScoped<IMailboxRepository, MailboxRepository>();
        services.TryAddScoped<IAliasRepository, AliasRepository>();

        // ---- SMTP inbound (Milestone 6) ----------------------------------------------------
        //
        // The message store is a singleton: it owns no per-request state, and its constructor
        // creates the storage directories, which should happen once at start rather than on
        // every message.
        services.TryAddSingleton<IMessageStore, FileSystemMessageStore>();

        services.TryAddScoped<IDeliveryRepository, DeliveryRepository>();

        // The read side, separate from the write side because the two have different callers:
        // local delivery writes and never reads, an IMAP session reads constantly.
        services.TryAddScoped<IImapMailboxReader, ImapMailboxReader>();
        services.TryAddScoped<IImapMailboxWriter, ImapMailboxWriter>();
        services.TryAddScoped<ILocalDeliveryService, LocalDeliveryService>();
        services.TryAddScoped<SmtpDataReceiver>();
        services.TryAddScoped<SmtpConnectionHandler>();

        // Scoped for the same reason the SMTP one is: its dependencies reach repositories, and a
        // handler shared across concurrent sessions would share their database connection.
        services.TryAddScoped<Imap.ImapConnectionHandler>();
        services.TryAddScoped<Pop3.Pop3ConnectionHandler>();

        // The POP3 maildrop lock is a singleton, and has to be: RFC 1939 §4's exclusive-access
        // lock exists to keep two sessions apart, and one held per scope would be held by every
        // connection separately, which is no lock at all.
        services.TryAddSingleton<Pop3.IPop3MaildropLocks, Pop3.Pop3MaildropLocks>();
        services.TryAddScoped<ISmtpDirectory, SmtpDirectory>();
        services.TryAddScoped<IMailboxAuthenticator, MailboxAuthenticator>();
        services.TryAddScoped<ISubmissionRateLimiter, SubmissionRateLimiter>();
        services.TryAddSingleton<SubmissionPolicy>();
        services.TryAddScoped<ISmtpQueries, Persistence.Queries.SmtpQueries>();
        services.TryAddSingleton<ISmtpConfigurationView, SmtpConfigurationView>();

        // Pure policies with configuration but no state, so one instance serves every session.
        services.TryAddSingleton<RelayPolicy>();
        services.TryAddSingleton<AliasExpansionPolicy>();


        services.TryAddScoped<IDomainRepository, DomainRepository>();
        services.TryAddScoped<IAuditRepository, AuditRepository>();

        services.TryAddScoped<IDomainQueries, DomainQueries>();
        services.TryAddScoped<IServerStatusQueries, ServerStatusQueries>();

        // ---- Outbound MTA (Milestone 8) ----------------------------------------------------
        services.TryAddScoped<IOutboundQueueRepository, OutboundQueueRepository>();

        // Singleton: the resolver's cache is exactly the thing that must be shared across every
        // delivery attempt, not rebuilt per scope. docs/DNS.md's TTL floor and ceiling are the
        // library's own cache bounds, configured once here.
        services.TryAddSingleton<ILookupClient>(_ => new LookupClient(new LookupClientOptions
        {
            UseCache = true,
            MinimumCacheTimeout = TimeSpan.FromSeconds(30),
            MaximumCacheTimeout = TimeSpan.FromHours(1),
            CacheFailedResults = true,
            FailedResultsCacheDuration = TimeSpan.FromSeconds(15),
            Timeout = TimeSpan.FromSeconds(10),
            Retries = 2,
            ThrowDnsErrors = false,
        }));
        services.TryAddSingleton<IMxDnsClient, LookupClientMxAdapter>();
        services.TryAddSingleton<IDnsResolver, DnsMxResolver>();

        // A second client, and deliberately not the one above. docs/DNS.md requires the
        // diagnostic resolver to bypass the cache: an operator who has just corrected a record
        // and is asking whether the correction took would otherwise be told about the old one,
        // which is the one question a diagnostic tool exists to answer. Failed results are not
        // cached either, for the same reason.
        services.TryAddSingleton<IDiagnosticDnsClient>(_ =>
            new LookupClientDiagnosticAdapter(new LookupClient(new LookupClientOptions
            {
                UseCache = false,
                CacheFailedResults = false,
                Timeout = TimeSpan.FromSeconds(10),
                Retries = 2,
                ThrowDnsErrors = false,
            })));
        services.TryAddSingleton<IDnsDiagnosticsService, DnsDiagnosticsService>();
        services.TryAddScoped<IdentityProbe>();
        services.TryAddScoped<AuthenticationProbe>();
        services.TryAddScoped<DnsProbe>();
        services.TryAddSingleton<IMtaStsPolicyFetcher, MtaStsPolicyFetcher>();
        services.TryAddScoped<TransportPolicyProbe>();

        // The other direction: the fetcher above reads other domains' policies to check them,
        // this composes the one this server publishes about itself. A singleton because the
        // policy's id is a hash of its content, and RFC 8461 §3.1 has senders re-fetch only when
        // that id changes - so the served bytes and the advertised id must be one fact.
        services.TryAddSingleton<IMtaStsPolicySource, MtaStsPolicySource>();

        // The delivery test. Scoped, because it reads the domain and DKIM repositories.
        services.TryAddScoped<IDeliveryTestService, DeliveryTestService>();

        // Stateless: it turns one string into one model and reaches nothing.
        services.TryAddSingleton<ITlsReportReader, TlsReportReader>();

        // The blocklists are whatever the operator named, and nothing by default: see
        // DeliverabilityOptions.BlockLists for why shipping a default set would be wrong.
        services.TryAddSingleton<IReputationProvider>(provider => new DnsBlockListProvider(
            provider.GetRequiredService<IDnsDiagnosticsService>(),
            [.. provider.GetRequiredService<IOptions<MailServerOptions>>().Value
                .Deliverability.BlockLists
                .Select(l => new ReputationList(l.Zone, l.Subject))],
            provider.GetRequiredService<IClock>()));
        services.TryAddScoped<ReputationProbe>();
        services.TryAddSingleton<IVolumeMeasure, DriveVolumeMeasure>();
        services.TryAddSingleton<IMessageStoreLocation>(provider => new ConfiguredMessageStoreLocation(
            provider.GetRequiredService<IOptions<MailServerOptions>>().Value.Storage.DataRoot));
        services.TryAddScoped<OperationsProbe>();
        services.TryAddScoped<IDeliverabilityReportService, DeliverabilityReportService>();
        services.TryAddScoped<IHeaderAnalysisService, HeaderAnalysisService>();
        services.TryAddScoped<IDnsPlanService, DnsPlanService>();
        services.TryAddScoped<IOutboundDeliveryClient, OutboundSmtpClient>();
        services.TryAddScoped<IDsnComposer, PlainTextDsnComposer>();

        // ---- DKIM (Milestone 9) -------------------------------------------------------------
        services.TryAddScoped<IDkimKeyRepository, DkimKeyRepository>();
        services.TryAddScoped<DkimKeyGenerator>();
        services.TryAddScoped<DkimMessageSigner>();
        services.TryAddScoped<DkimMessageVerifier>();

        // Singleton, mirroring IMxDnsClient/IDnsResolver above: a stateless adapter over the
        // same ILookupClient singleton, so no reason to rebuild it per scope.
        services.TryAddSingleton<IDkimDnsClient, LookupClientDkimAdapter>();
        services.TryAddSingleton<IDkimPublicKeyResolver, DnsDkimPublicKeyResolver>();

        // ---- SPF (Milestone 9) --------------------------------------------------------------
        services.TryAddSingleton<ITxtDnsClient, LookupClientTxtAdapter>();
        services.TryAddSingleton<ITxtRecordResolver, DnsTxtRecordResolver>();
        services.TryAddScoped<SpfEvaluator>();

        // ---- DMARC (Milestone 9) ------------------------------------------------------------
        services.TryAddSingleton<PublicSuffixListLoader>();
        services.TryAddSingleton<IPublicSuffixListProvider>(sp => sp.GetRequiredService<PublicSuffixListLoader>());
        services.TryAddScoped<DmarcEvaluator>();

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
