using System.ComponentModel.DataAnnotations;
using MailServer.Domain.Enums;

namespace MailServer.Infrastructure.Configuration;

/// <summary>
/// The root of the server's strongly-typed configuration.
/// </summary>
/// <remarks>
/// <para>
/// Bound once at startup and validated before any listener opens. Invalid configuration
/// prevents the service from starting rather than producing a subtly wrong server: a mail
/// server running with the wrong <c>Hostname</c> sends mail that fails reverse-DNS checks
/// at every major receiver, which is far worse than a service that refuses to start with a
/// clear message.
/// </para>
/// <para>
/// <b>No secrets live here.</b> Connection-string passwords, smarthost credentials and
/// certificate passphrases are held in the DPAPI-protected secret store; configuration
/// carries only the <i>name</i> of the secret to look up.
/// </para>
/// <para>
/// Properties are settable because the configuration binder requires it. They are treated
/// as immutable after startup; nothing in the product writes to them at runtime.
/// </para>
/// </remarks>
public sealed class MailServerOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "MailServer";

    public ServerOptions Server { get; set; } = new();

    public DatabaseOptions Database { get; set; } = new();

    public StorageOptions Storage { get; set; } = new();

    public IpcOptions Ipc { get; set; } = new();

    public SecurityOptions Security { get; set; } = new();

    public LimitsOptions Limits { get; set; } = new();

    public MaintenanceOptions Maintenance { get; set; } = new();

    public CertificateOptions Certificates { get; set; } = new();

    public AcmeOptions Acme { get; set; } = new();
}

/// <summary>The server's own identity.</summary>
public sealed class ServerOptions
{
    /// <summary>
    /// The server's fully-qualified mail hostname, e.g. <c>mail.example.com</c>.
    /// </summary>
    /// <remarks>
    /// The single most consequential setting in the product: it is announced in EHLO, must
    /// match the PTR record for the sending IP, must appear in the TLS certificate's SAN
    /// list, and is what the MX record points at. Four things that must agree, configured in
    /// one place.
    /// </remarks>
    [Required(AllowEmptyStrings = false)]
    public string Hostname { get; set; } = "mail.localhost.local";

    /// <summary>The public IP address mail is sent from, when it is known and static.</summary>
    public string? PublicIpAddress { get; set; }

    /// <summary>Product name used in SMTP banners and generated headers.</summary>
    public string ProductName { get; set; } = "AetherMail Server";
}

/// <summary>Database provider selection and per-provider settings.</summary>
public sealed class DatabaseOptions
{
    /// <summary>Which provider to use.</summary>
    public DatabaseProvider Provider { get; set; } = DatabaseProvider.Sqlite;

    public SqliteOptions Sqlite { get; set; } = new();

    public SqlServerOptions SqlServer { get; set; } = new();

    public MigrationOptions Migrations { get; set; } = new();
}

/// <summary>Supported database providers.</summary>
public enum DatabaseProvider
{
    /// <summary>Development, testing, personal servers and small installations.</summary>
    Sqlite = 0,

    /// <summary>The recommended provider for production.</summary>
    SqlServer = 1,
}

/// <summary>SQLite settings.</summary>
/// <remarks>
/// The defaults here are not cosmetic. WAL lets IMAP readers proceed while the queue writes;
/// a busy timeout turns <c>SQLITE_BUSY</c> into a bounded wait instead of an immediate
/// failure; and foreign keys are OFF by default in SQLite, so referential integrity has to
/// be asked for explicitly on every connection.
/// </remarks>
public sealed class SqliteOptions
{
    /// <summary>Path to the database file.</summary>
    [Required(AllowEmptyStrings = false)]
    public string DataSource { get; set; } = "mailserver.db";

    /// <summary>How long to wait for the writer before failing, in milliseconds.</summary>
    [Range(0, 120_000)]
    public int BusyTimeoutMs { get; set; } = 5_000;

    /// <summary>Journal mode. WAL unless there is a specific reason otherwise.</summary>
    public string JournalMode { get; set; } = "WAL";

    /// <summary>
    /// Synchronous mode. NORMAL is durable across a process crash under WAL and is far
    /// cheaper per queue update than FULL.
    /// </summary>
    public string Synchronous { get; set; } = "NORMAL";

    /// <summary>Page cache size in KiB.</summary>
    [Range(64, 1_048_576)]
    public int CacheSizeKilobytes { get; set; } = 16_384;

    /// <summary>Enforce foreign keys. Leave on.</summary>
    public bool EnforceForeignKeys { get; set; } = true;
}

/// <summary>SQL Server settings.</summary>
public sealed class SqlServerOptions
{
    /// <summary>
    /// Connection string for development only. In production, leave this empty and use
    /// <see cref="ConnectionStringSecretName"/> so no credential is ever written to a JSON
    /// file that ends up in a support ticket or a source-control repository.
    /// </summary>
    public string? ConnectionString { get; set; }

    /// <summary>Name under which the connection string is held in the protected secret store.</summary>
    public string? ConnectionStringSecretName { get; set; }

    [Range(1, 600)]
    public int CommandTimeoutSeconds { get; set; } = 30;

    [Range(0, 20)]
    public int MaxRetryAttempts { get; set; } = 5;
}

/// <summary>Migration runner behaviour.</summary>
public sealed class MigrationOptions
{
    /// <summary>
    /// Apply pending migrations at startup. On by default: an installation that silently
    /// runs against an out-of-date schema fails in far more confusing ways than one that
    /// migrates or refuses to start.
    /// </summary>
    public bool RunOnStartup { get; set; } = true;

    /// <summary>Take a backup before applying any migration marked destructive.</summary>
    public bool BackupBeforeDestructive { get; set; } = true;

    /// <summary>Per-script timeout in seconds.</summary>
    [Range(1, 3_600)]
    public int CommandTimeoutSeconds { get; set; } = 300;
}

/// <summary>Filesystem layout and size limits.</summary>
public sealed class StorageOptions
{
    /// <summary>Root of all runtime data.</summary>
    [Required(AllowEmptyStrings = false)]
    public string DataRoot { get; set; } = "Data";

    /// <summary>Largest message accepted anywhere on the server. Per-domain limits may be lower.</summary>
    [Range(64 * 1024L, 1024L * 1024 * 1024)]
    public long MaxMessageSizeBytes { get; set; } = 35L * 1024 * 1024;

    /// <summary>Free space below which storage health becomes Critical and inbound mail is deferred.</summary>
    [Range(0, long.MaxValue)]
    public long MinimumFreeDiskBytes { get; set; } = 2L * 1024 * 1024 * 1024;
}

/// <summary>Named-pipe IPC settings.</summary>
public sealed class IpcOptions
{
    /// <summary>Pipe name, without the <c>\\.\pipe\</c> prefix.</summary>
    [Required(AllowEmptyStrings = false)]
    public string PipeName { get; set; } = "AetherMail.Admin";

    /// <summary>
    /// Largest single frame accepted, in bytes. A hard cap read before any allocation, so a
    /// malicious or buggy client cannot exhaust service memory by declaring a huge length.
    /// </summary>
    [Range(4_096, 64 * 1024 * 1024)]
    public int MaxFrameBytes { get; set; } = 4 * 1024 * 1024;

    [Range(1, 600)]
    public int RequestTimeoutSeconds { get; set; } = 60;

    /// <summary>Concurrent admin connections accepted.</summary>
    [Range(1, 64)]
    public int MaxConcurrentConnections { get; set; } = 8;
}

/// <summary>Security settings.</summary>
public sealed class SecurityOptions
{
    /// <summary>Which secret-protection scheme to use.</summary>
    public SecretProtectionScheme SecretProtection { get; set; } = SecretProtectionScheme.Dpapi;

    /// <summary>Failed administrator sign-ins before lockout.</summary>
    [Range(1, 100)]
    public int AdminLockoutThreshold { get; set; } = 5;

    /// <summary>
    /// Duration of the first lockout. Subsequent lockouts double, up to
    /// <see cref="AdminLockoutMaximumMinutes"/>.
    /// </summary>
    [Range(1, 1_440)]
    public int AdminLockoutMinutes { get; set; } = 15;

    /// <summary>Ceiling on the escalated lockout duration.</summary>
    [Range(1, 10_080)]
    public int AdminLockoutMaximumMinutes { get; set; } = 480;

    /// <summary>Idle period after which the failure counter resets.</summary>
    [Range(1, 10_080)]
    public int AdminLockoutCounterResetMinutes { get; set; } = 60;

    /// <summary>
    /// Idle minutes before an administrative session ends and the console locks.
    /// </summary>
    /// <remarks>
    /// Enforced server-side on the session, not merely by a client-side timer. A client that
    /// simply declined to lock itself would otherwise keep a session alive indefinitely.
    /// </remarks>
    [Range(1, 1_440)]
    public int AutoLockMinutes { get; set; } = 10;

    /// <summary>
    /// Hard lifetime of a session regardless of activity.
    /// </summary>
    /// <remarks>
    /// A sliding idle window alone means a console left open on an unattended desktop, with
    /// something periodically refreshing it, stays authenticated forever.
    /// </remarks>
    [Range(1, 168)]
    public int SessionMaximumHours { get; set; } = 12;

    /// <summary>Minimum acceptable master password length.</summary>
    [Range(8, 128)]
    public int MinimumPasswordLength { get; set; } = 12;

    /// <summary>
    /// Argon2id memory cost in kibibytes. 65536 is 64 MiB, per RFC 9106.
    /// </summary>
    /// <remarks>
    /// The memory cost is what makes parallel GPU cracking expensive. Lowering it to speed up
    /// sign-in trades away the main thing Argon2 provides over PBKDF2.
    /// </remarks>
    [Range(8_192, 1_048_576)]
    public int Argon2MemoryKib { get; set; } = 65_536;

    /// <summary>Argon2id time cost: number of passes.</summary>
    [Range(1, 20)]
    public int Argon2Iterations { get; set; } = 3;

    /// <summary>Argon2id degree of parallelism (lanes).</summary>
    [Range(1, 16)]
    public int Argon2Parallelism { get; set; } = 2;
}

/// <summary>Available secret-protection schemes.</summary>
public enum SecretProtectionScheme
{
    /// <summary>Windows DPAPI at machine scope with additional entropy. The production scheme.</summary>
    Dpapi = 0,

    /// <summary>
    /// Development-only file-backed key. Refuses to initialise in a Production environment
    /// and logs a Critical warning on every start. Exists so the server can be developed and
    /// tested on a non-Windows machine, not as a fallback for Windows deployments.
    /// </summary>
    Development = 1,
}

/// <summary>Protocol and resource limits.</summary>
/// <remarks>
/// Every one of these exists to bound an attacker-controlled quantity. Brief rule 76
/// (resource-exhaustion protection) is implemented as concrete numbers here rather than as
/// scattered magic constants, so an operator can see and tune the whole envelope in one place.
/// </remarks>
public sealed class LimitsOptions
{
    [Range(1, 10_000)]
    public int MaxRecipientsPerMessage { get; set; } = 100;

    [Range(1, 10_000)]
    public int MaxConcurrentConnectionsPerIp { get; set; } = 10;

    [Range(1, 100_000)]
    public int MaxConcurrentConnectionsTotal { get; set; } = 500;

    [Range(10, 3_600)]
    public int SmtpCommandTimeoutSeconds { get; set; } = 300;

    [Range(10, 7_200)]
    public int SmtpSessionTimeoutSeconds { get; set; } = 600;

    /// <summary>
    /// Longest SMTP command line accepted. RFC 5321 requires 512 octets for commands and
    /// 1000 for the text line; the larger default accommodates long ESMTP parameter lists
    /// while still bounding the read.
    /// </summary>
    [Range(512, 65_536)]
    public int MaxSmtpLineBytes { get; set; } = 4_096;

    [Range(4_096, 4 * 1024 * 1024)]
    public int MaxHeaderBytes { get; set; } = 256 * 1024;

    /// <summary>Maximum MIME nesting depth. Bounds the MIME-bomb attack.</summary>
    [Range(1, 200)]
    public int MaxMimeDepth { get; set; } = 20;

    [Range(1, 20)]
    public int MaxAuthAttemptsPerSession { get; set; } = 3;
}

/// <summary>Startup maintenance mode.</summary>
public sealed class MaintenanceOptions
{
    /// <summary>
    /// Mode to apply when no mode has been persisted. The persisted value wins, so an
    /// operator who paused outbound delivery to investigate a problem does not find it
    /// resumed by a reboot.
    /// </summary>
    public string Mode { get; set; } = "Normal";
}

/// <summary>TLS certificate settings.</summary>
public sealed class CertificateOptions
{
    /// <summary>
    /// Whether to generate a self-signed certificate at first start when none is configured.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the <b>only</b> circumstance in which this server creates a self-signed
    /// certificate on its own. It exists so that a freshly installed server can complete a TLS
    /// handshake at all — without it, the administration application's first connection and
    /// every early diagnostic would fail against a server with no certificate.
    /// </para>
    /// <para>
    /// It never replaces an existing certificate, and it is never used as a fallback when a
    /// renewal fails. See <c>CertificateRenewalPolicy</c>.
    /// </para>
    /// </remarks>
    public bool GenerateSelfSignedOnFirstStart { get; set; } = true;

    /// <summary>RSA key size for generated certificates.</summary>
    [Range(2048, 4096)]
    public int SelfSignedKeySizeBits { get; set; } = 3072;

    /// <summary>Validity in years for generated certificates.</summary>
    [Range(1, 5)]
    public int SelfSignedValidityYears { get; set; } = 1;

    /// <summary>Days before expiry at which renewal is first attempted.</summary>
    [Range(1, 90)]
    public int RenewalWindowDays { get; set; } = 30;

    /// <summary>How often the lifecycle service checks certificate expiry.</summary>
    [Range(1, 168)]
    public int LifecycleCheckIntervalHours { get; set; } = 12;

    /// <summary>
    /// Prefer the Windows certificate store over protected PFX files where both are available.
    /// </summary>
    /// <remarks>
    /// True on Windows in production, because a key held in the store never becomes a file on
    /// disk. Automatically inert on other platforms, where there is no store to prefer.
    /// </remarks>
    public bool PreferWindowsCertificateStore { get; set; } = true;
}

/// <summary>ACME / Let's Encrypt settings.</summary>
public sealed class AcmeOptions
{
    /// <summary>
    /// Which directory to use: <c>LetsEncryptStaging</c>, <c>LetsEncryptProduction</c> or
    /// <c>Custom</c>.
    /// </summary>
    /// <remarks>
    /// <b>Staging by default, and that is not timidity.</b> An operator fixing DNS while
    /// retrying against production exhausts the five-duplicate-certificates-per-week limit in
    /// an afternoon and then waits a week with nothing to show for it. Staging proves the flow
    /// works, costs no production quota, and the certificates it issues are valid in every
    /// respect except being publicly trusted.
    /// </remarks>
    public AcmeDirectory Directory { get; set; } = AcmeDirectory.LetsEncryptStaging;

    /// <summary>Directory endpoint when <see cref="Directory"/> is <c>Custom</c>.</summary>
    public string? CustomDirectoryUrl { get; set; }

    /// <summary>Address the CA sends expiry warnings to.</summary>
    [EmailAddress]
    public string? ContactEmail { get; set; }

    /// <summary>
    /// Whether the operator accepts the CA's terms of service.
    /// </summary>
    /// <remarks>
    /// Defaults to false and must be set deliberately. Registration fails with a clear message
    /// until it is: accepting a legal agreement on an operator's behalf because it was
    /// convenient is not this software's decision.
    /// </remarks>
    public bool AcceptTermsOfService { get; set; }

    /// <summary>Challenge type used unless one is chosen per request.</summary>
    public AcmeChallengeType ChallengeType { get; set; } = AcmeChallengeType.Http01;

    /// <summary>Whether the service runs the HTTP-01 challenge endpoint itself.</summary>
    public bool EnableHttpChallengeListener { get; set; } = true;

    /// <summary>Port the HTTP-01 endpoint listens on.</summary>
    [Range(1, 65_535)]
    public int HttpChallengePort { get; set; } = 80;

    /// <summary>
    /// Resolvers queried when checking whether a DNS-01 record has propagated.
    /// </summary>
    /// <remarks>
    /// Should be the zone's authoritative nameservers. The defaults are public recursive
    /// resolvers, which is a compromise noted in docs/LetsEncrypt.md: they can serve a cached
    /// negative answer after a record is live, so a check that says "not yet" is worth
    /// repeating.
    /// </remarks>
    public IList<string> ChallengeCheckResolvers { get; set; } = ["1.1.1.1", "8.8.8.8"];

    /// <summary>Key size for issued certificates.</summary>
    [Range(2048, 4096)]
    public int CertificateKeySizeBits { get; set; } = 3072;
}
