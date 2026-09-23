using System.ComponentModel.DataAnnotations;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Deliverability;

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

    public SmtpOptions Smtp { get; set; } = new();

    public ImapOptions Imap { get; set; } = new();

    public Pop3Options Pop3 { get; set; } = new();

    public DeliverabilityOptions Deliverability { get; set; } = new();

    public OutboundOptions Outbound { get; set; } = new();

    public FilteringOptions Filtering { get; set; } = new();
}

/// <summary>The IMAP listeners.</summary>
/// <remarks>
/// <para>
/// Both listeners are <b>disabled by default</b>, and that is the same decision
/// <see cref="SmtpOptions"/> makes for submission: a port nobody asked for is a port nobody is
/// watching. Mailbox access is the one service on this server that reaches a user's entire mail
/// history, so it opens when an operator says so.
/// </para>
/// <para>
/// Port 993 is the one to enable. RFC 8314 §3 prefers implicit TLS over <c>STARTTLS</c> for
/// exactly the reason this server is careful about the upgrade: there is no cleartext phase for
/// a stripping attacker to interfere with, because the handshake precedes the protocol
/// entirely. Port 143 exists for clients that cannot do that, and it refuses <c>LOGIN</c> until
/// TLS is negotiated.
/// </para>
/// </remarks>
public sealed class ImapOptions
{
    /// <summary>Port 143. Cleartext on connect; TLS is reached through <c>STARTTLS</c>.</summary>
    public ImapListenerOptions Cleartext { get; set; } = new() { Port = 143, Enabled = false };

    /// <summary>Port 993. TLS from the first byte, before the greeting.</summary>
    public ImapListenerOptions ImplicitTls { get; set; } = new() { Port = 993, Enabled = false };

    /// <summary>
    /// Whether <c>LOGIN</c> and <c>AUTHENTICATE</c> are offered.
    /// </summary>
    /// <remarks>
    /// The flag that keeps the capability listing honest: false advertises
    /// <c>LOGINDISABLED</c> and refuses both commands, which is the truthful pairing while
    /// mailbox access is still being built. Turning it on without the commands behind it would
    /// advertise an authentication this server cannot complete.
    /// </remarks>
    public bool EnableAuthentication { get; set; }
}

/// <summary>The POP3 listeners.</summary>
/// <remarks>
/// <para>
/// Both listeners are <b>disabled by default</b>, as the IMAP ones are, and POP3 has a reason of
/// its own to stay shut: RFC 1939 §8 describes what a maildrop becomes when clients use it as a
/// repository — "there has been a tendency for already-read messages to accumulate on the server
/// without bound" — and §5's numbering makes a maildrop of thousands of messages expensive to
/// open. It is here for the devices that cannot speak IMAP, not as an alternative to it.
/// </para>
/// <para>
/// Port 995 is the one to enable. RFC 8314 §3.1 has the TLS handshake begin immediately there,
/// so there is no cleartext phase for a stripping attacker to interfere with; port 110 exists
/// for clients that cannot do that, and it refuses <c>USER</c> and <c>PASS</c> until
/// <c>STLS</c> has run.
/// </para>
/// </remarks>
public sealed class Pop3Options
{
    /// <summary>Port 110. Cleartext on connect; TLS is reached through <c>STLS</c>.</summary>
    public Pop3ListenerOptions Cleartext { get; set; } = new() { Port = 110, Enabled = false };

    /// <summary>Port 995. TLS from the first byte, before the greeting.</summary>
    public Pop3ListenerOptions ImplicitTls { get; set; } = new() { Port = 995, Enabled = false };

    /// <summary>
    /// Whether <c>USER</c> and <c>PASS</c> are offered.
    /// </summary>
    /// <remarks>
    /// The flag that keeps the capability listing honest: false announces no <c>USER</c>
    /// capability and refuses both commands, which RFC 2449 §6.2 makes the correct pairing — that
    /// capability "indicates that the USER and PASS commands are supported".
    /// </remarks>
    public bool EnableAuthentication { get; set; }
}

/// <summary>The deliverability report's settings.</summary>
/// <remarks>
/// Only the reputation lists so far. Everything else the report needs it reads from the
/// configuration the mail server already has — the hostname, the certificate, the domains — and
/// a diagnostic tool that had its own idea of any of those would be diagnosing a server nobody
/// is running.
/// </remarks>
/// <summary>
/// The anti-spam filter, the malware seam and the quarantine.
/// </summary>
/// <remarks>
/// <b>On by default, and refusing mail by default is not.</b> The checks that run without an
/// operator configuring anything — authentication weighting, the structural heuristics, the
/// attachment names — are cheap, need no network and no corpus, and their worst outcome is a
/// message in a junk folder. Rejection is the one action that leaves nothing behind, and
/// <c>FilterPolicy.RejectThreshold</c> defaults to infinity so no score reaches it.
/// </remarks>
public sealed class FilteringOptions
{
    /// <summary>Whether the filter runs at all.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>At or above this score, a message goes to the recipient's <c>\Junk</c> folder.</summary>
    public double JunkThreshold { get; set; } = 5.0;

    /// <summary>At or above this score, a message is held for an operator.</summary>
    public double QuarantineThreshold { get; set; } = 10.0;

    /// <summary>
    /// At or above this score, a message is refused at SMTP time. Zero or negative means never.
    /// </summary>
    /// <remarks>
    /// <b>Never, by default.</b> Heuristic scoring is wrong often enough that a server which
    /// discards mail on it will eventually discard something that mattered, and nobody will
    /// know, because a rejection leaves nothing to find. An operator who wants that trade can
    /// have it; they should have to ask.
    /// </remarks>
    public double RejectThreshold { get; set; }

    /// <summary>How long a held message is kept before a sweep may remove it.</summary>
    /// <remarks>
    /// Fixed onto each row at hold time, so shortening this does not retroactively expire what
    /// is already held.
    /// </remarks>
    public int QuarantineRetentionDays { get; set; } = 30;

    /// <summary>Whether to consult the configured block lists about the sending host.</summary>
    /// <remarks>
    /// Separate from <c>Deliverability:BlockLists</c> being populated, because the readiness
    /// report's use of those lists is a handful of queries an operator asked for, and this one
    /// is a query per inbound message. An operator should be able to have the first without the
    /// second.
    /// </remarks>
    public bool UseBlockLists { get; set; }

    /// <summary>
    /// Whether a message a malware scanner could not examine is held rather than delivered.
    /// </summary>
    /// <remarks>
    /// Off, because a mail server that stops delivering when an optional component dies is the
    /// worse surprise. An operator who requires scanning can turn it on, and should expect a
    /// scanner outage to fill the quarantine.
    /// </remarks>
    public bool FailClosedOnScannerError { get; set; }
}

public sealed class DeliverabilityOptions
{
    /// <summary>
    /// The DNS blocklists to query, empty by default.
    /// </summary>
    /// <remarks>
    /// <b>Empty is the correct default and not an omission.</b> Querying a list is a request this
    /// server makes, on the operator's behalf, to an organisation they have not chosen; most of
    /// these lists are run by volunteers, and several forbid automated use without an
    /// arrangement. Shipping a default set would have every installation start querying them on
    /// somebody else's say-so.
    /// </remarks>
    public IList<ReputationListOptions> BlockLists { get; set; } = [];

    /// <summary>The MTA-STS policy this server publishes for its own domain.</summary>
    public MtaStsOptions MtaSts { get; set; } = new();

    /// <summary>Collecting the TLS reports other senders deliver.</summary>
    public TlsRptOptions TlsRpt { get; set; } = new();
}

/// <summary>
/// The MTA-STS policy this server publishes, and the endpoint that serves it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Disabled by default, and that is not timidity.</b> RFC 8461 §8.3 is blunt about what a
/// mistake here costs: a policy in <c>enforce</c> mode whose <c>mx</c> list is wrong makes
/// conforming senders <i>refuse to deliver</i>, and they go on refusing for
/// <see cref="MaxAgeSeconds"/> because they cached it. Every other check in this product reports
/// a problem; this one is the only setting that can create an outage for mail that was arriving
/// perfectly well, and it needs three things an installer cannot verify on its own — a
/// <c>mta-sts.</c> hostname in DNS, a trusted certificate for it, and an <c>mx</c> list that
/// really is every host that accepts this domain's mail.
/// </para>
/// <para>
/// <b>Start in <see cref="MtaStsMode.Testing"/>.</b> §8.3 recommends exactly that: senders
/// report failures through TLS-RPT and deliver anyway, so a wrong <c>mx</c> list shows up as a
/// report rather than as a bounce. Move to <c>enforce</c> once the reports are quiet.
/// </para>
/// </remarks>
public sealed class MtaStsOptions
{
    /// <summary>Whether to serve a policy at all.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// What senders should do when validation fails.
    /// </summary>
    /// <remarks>
    /// Testing by default, per RFC 8461 §8.3 — see this class's own remarks for why the
    /// difference between this and <c>enforce</c> is the difference between a report and an
    /// outage.
    /// </remarks>
    public MtaStsMode Mode { get; set; } = MtaStsMode.Testing;

    /// <summary>
    /// The hosts this domain's mail may be delivered to.
    /// </summary>
    /// <remarks>
    /// Every host with an MX record for this domain, including any backup exchanger. A host
    /// missing from this list is one a conforming sender in <c>enforce</c> mode will not deliver
    /// to. Patterns follow §4.1: <c>*</c> may stand only for the entire leftmost label.
    /// </remarks>
    public IList<string> MxHosts { get; set; } = [];

    /// <summary>
    /// How long senders may cache the policy, in seconds. One week by default.
    /// </summary>
    /// <remarks>
    /// §3.2 caps it at 31557600 and the value is capped rather than refused. The trade is
    /// symmetric and worth understanding: a long age is a stronger defence, because a
    /// downgrade attacker has to outlast every sender's cache, and a longer mistake, because a
    /// wrong policy stays wrong for senders that already fetched it. A week is the usual
    /// starting point.
    /// </remarks>
    [Range(0, MtaStsPolicy.MaxAgeCeiling)]
    public long MaxAgeSeconds { get; set; } = 604_800;

    /// <summary>
    /// The port the policy endpoint listens on. 443, and effectively fixed.
    /// </summary>
    /// <remarks>
    /// RFC 8461 §3.2 has senders fetch <c>https://mta-sts.&lt;domain&gt;/.well-known/mta-sts.txt</c>
    /// and §3.3 forbids them from following a redirect, so a policy on another port is a policy
    /// nobody fetches. Configurable only for a reverse proxy that forwards to it.
    /// </remarks>
    [Range(1, 65535)]
    public int Port { get; set; } = 443;
}

/// <summary>One DNS blocklist to query.</summary>
public sealed class ReputationListOptions
{
    /// <summary>
    /// The list's DNS zone, such as <c>zen.spamhaus.org</c>.
    /// </summary>
    /// <remarks>
    /// The zone alone, with no query prefix: RFC 5782 §2.1 builds the name by prepending the
    /// reversed address to it, and a value that already carried one would produce a name no
    /// list serves — which looks exactly like never being listed.
    /// </remarks>
    [Required]
    [RegularExpression(
        @"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$",
        ErrorMessage = "A blocklist zone must be a domain name, such as zen.spamhaus.org.")]
    public string Zone { get; set; } = string.Empty;

    /// <summary>
    /// Whether this list is about addresses or about domains.
    /// </summary>
    /// <remarks>
    /// Not inferred, because getting it wrong is silent: RFC 5782 §5 gives the two kinds
    /// different test entries, so a domain list asked with an address list's test entries reports
    /// as not answering, and its verdicts are discarded without anybody being told why.
    /// </remarks>
    public ReputationListSubject Subject { get; set; } = ReputationListSubject.Address;
}

/// <summary>One POP3 listener's endpoint.</summary>
/// <remarks>
/// The same three members as <see cref="ImapListenerOptions"/>, and deliberately not the same
/// type, for the reason that class gives: a configuration class is a published schema, and
/// sharing one between two protocols' sections would mean that adding a setting for one silently
/// adds it to the other.
/// </remarks>
public sealed class Pop3ListenerOptions
{
    public bool Enabled { get; set; }

    [Range(1, 65_535)]
    public int Port { get; set; }

    /// <summary>Addresses to bind. Empty means every interface.</summary>
    public IList<string> BindAddresses { get; set; } = [];
}

/// <summary>One IMAP listener's endpoint.</summary>
/// <remarks>
/// The same three members as <see cref="SmtpListenerOptions"/>, and deliberately not the same
/// type. A configuration class is a published schema: sharing one between two protocols' sections
/// would mean that adding a setting for one silently adds it to the other, and that narrowing a
/// validation range for one narrows it for both. The duplication is three properties; the
/// coupling it avoids is every future change to either.
/// </remarks>
public sealed class ImapListenerOptions
{
    public bool Enabled { get; set; }

    [Range(1, 65_535)]
    public int Port { get; set; }

    /// <summary>
    /// Addresses to bind. Empty means every interface.
    /// </summary>
    /// <remarks>
    /// Listed explicitly rather than assumed, so an operator who wants mailbox access reachable
    /// only from an internal interface can say so instead of relying on a firewall to undo a
    /// default.
    /// </remarks>
    public IList<string> BindAddresses { get; set; } = [];
}

/// <summary>The outbound queue and delivery client.</summary>
public sealed class OutboundOptions
{
    /// <summary>How many due items one worker claims per poll.</summary>
    [Range(1, 1_000)]
    public int ClaimBatchSize { get; set; } = 20;

    /// <summary>
    /// How long a claimed item is leased before another worker may reclaim it.
    /// </summary>
    /// <remarks>
    /// Must comfortably exceed the longest a single delivery attempt can plausibly take
    /// (connect, STARTTLS, and a multi-recipient DATA transfer) - a lease shorter than one
    /// attempt would let a second worker "reclaim" an item that is still being worked on.
    /// </remarks>
    [Range(30, 3_600)]
    public int LeaseDurationSeconds { get; set; } = 300;

    /// <summary>How often the scheduler polls for due work when the queue is empty.</summary>
    [Range(1, 300)]
    public int PollIntervalSeconds { get; set; } = 5;

    /// <summary>Concurrent deliveries permitted to one destination domain at once.</summary>
    /// <remarks>
    /// The per-domain throttle <c>docs/Architecture.md</c> §8 requires: without it, a large
    /// backlog for one slow-to-answer domain would consume every worker, starving delivery to
    /// every other domain in the queue.
    /// </remarks>
    [Range(1, 100)]
    public int MaxConcurrentDeliveriesPerDomain { get; set; } = 4;

    /// <summary>Total concurrent deliveries across every domain.</summary>
    [Range(1, 1_000)]
    public int MaxConcurrentDeliveriesTotal { get; set; } = 20;

    /// <summary>Longest wait for a TCP connection to a remote MX.</summary>
    [Range(1, 120)]
    public int ConnectTimeoutSeconds { get; set; } = 30;

    /// <summary>Longest wait for a reply to any single command, including the banner and STARTTLS.</summary>
    [Range(1, 300)]
    public int CommandTimeoutSeconds { get; set; } = 60;

    /// <summary>Longest wait for the final reply after the message body has been sent.</summary>
    /// <remarks>
    /// Separate from <see cref="CommandTimeoutSeconds"/> because a large message can take a
    /// receiving server much longer to scan and commit than any other single step in the
    /// conversation, and timing it out at the same bound as <c>EHLO</c> would defer mail that
    /// was, in fact, about to succeed.
    /// </remarks>
    [Range(1, 1_800)]
    public int DataTimeoutSeconds { get; set; } = 300;

    /// <summary>Port used to connect directly to a resolved MX host.</summary>
    [Range(1, 65_535)]
    public int DeliveryPort { get; set; } = 25;

    /// <summary>
    /// Backoff schedule in minutes, ascending. Null uses <c>RetryBackoffPolicy</c>'s own default.
    /// </summary>
    public IList<int>? RetryScheduleMinutes { get; set; }

    /// <summary>How many days a message is retried before it is bounced.</summary>
    [Range(1, 30)]
    public int MaximumLifetimeDays { get; set; } = 5;

    /// <summary>Age at which a "delivery is delayed" warning DSN is sent.</summary>
    [Range(1, 720)]
    public int DelayWarningThresholdHours { get; set; } = 4;
}

/// <summary>The SMTP listeners.</summary>
/// <remarks>
/// Three separate listeners rather than one with switches. Conflating MTA receipt with client
/// submission is the root cause of most open relays in the wild: a single listener with an
/// "allow relay" flag is one misconfiguration away from relaying for the Internet, and the flag
/// is always set by somebody solving a different problem.
/// </remarks>
public sealed class SmtpOptions
{
    /// <summary>Port 25. Mail from the Internet for local domains.</summary>
    public SmtpListenerOptions InboundMta { get; set; } = new() { Port = 25, Enabled = true };

    /// <summary>Port 587. Authenticated submission, STARTTLS before AUTH.</summary>
    /// <remarks>
    /// The port RFC 6409 designates for submission, and the one a mail client should be
    /// configured to use. It requires AUTH, and AUTH requires TLS, so a client that reaches it
    /// without either is refused rather than accommodated.
    /// </remarks>
    public SmtpListenerOptions Submission { get; set; } = new() { Port = 587, Enabled = true };

    /// <summary>
    /// Port 465. Authenticated submission, TLS from the first octet.
    /// </summary>
    /// <remarks>
    /// RFC 8314 recommends implicit TLS over STARTTLS for submission, because there is no
    /// plaintext phase for a network attacker to strip. Enabled alongside 587 rather than
    /// instead of it: a great many existing clients are configured for one or the other, and
    /// turning off the one a customer already uses is a migration, not a default.
    /// </remarks>
    public SmtpListenerOptions ImplicitTlsSubmission { get; set; } = new() { Port = 465, Enabled = true };

    /// <summary>
    /// Whether SASL authentication is offered.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Gates the AUTH capability. It remains a switch rather than becoming unconditional so that
    /// an operator running this server purely as an inbound MTA can turn the whole submission
    /// surface off — the smallest attack surface is the one that is not there.
    /// </para>
    /// <para>
    /// Turning it off does <b>not</b> make the submission listeners accept unauthenticated mail:
    /// they refuse every sender instead. See <c>SmtpCommandProcessor.RequiresAuthentication</c>.
    /// </para>
    /// </remarks>
    public bool EnableAuthentication { get; set; } = true;

    /// <summary>Whether SMTPUTF8 is implemented and enabled.</summary>
    public bool EnableSmtpUtf8 { get; set; }

    /// <summary>Whether BDAT/CHUNKING is implemented and enabled.</summary>
    public bool EnableChunking { get; set; }

    /// <summary>
    /// Addresses permitted to relay without authenticating.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The narrow, deliberately awkward escape hatch for an internal application that cannot
    /// authenticate — a printer, a monitoring box, a legacy line-of-business system.
    /// </para>
    /// <para>
    /// <b>Empty by default, and it must stay that way unless somebody types an address.</b> It is
    /// a list of individual addresses, not a subnet: "the local network" is exactly how an open
    /// relay is configured by accident, because the local network is bigger than whoever wrote
    /// the rule believed. Each entry is a host an operator decided to trust, one at a time.
    /// </para>
    /// </remarks>
    public IList<string> AuthorizedRelayAddresses { get; set; } = [];

    /// <summary>
    /// How long a graceful shutdown waits for in-flight sessions.
    /// </summary>
    /// <remarks>
    /// Abandoning a session mid-DATA risks a duplicate at the sending server: it saw no reply,
    /// so it retries, and this server may already have delivered the copy it received.
    /// </remarks>
    [Range(1, 300)]
    public int ShutdownGraceSeconds { get; set; } = 30;
}

/// <summary>One listener.</summary>
public sealed class SmtpListenerOptions
{
    public bool Enabled { get; set; }

    [Range(1, 65_535)]
    public int Port { get; set; }

    /// <summary>
    /// Addresses to bind. Empty means every interface.
    /// </summary>
    /// <remarks>
    /// Listed explicitly rather than assumed, so an operator who wants the submission port on an
    /// internal interface only can say so instead of relying on a firewall to undo a default.
    /// </remarks>
    public IList<string> BindAddresses { get; set; } = [];
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

    /// <summary>
    /// Connections one address may open in an hour, across every SMTP listener.
    /// </summary>
    /// <remarks>
    /// The complement to <see cref="MaxConcurrentConnectionsPerIp"/>, which a peer that
    /// connects, delivers and disconnects never reaches however fast it repeats. Set from what
    /// a real exchanger does: a large provider working through a backlog opens connections in
    /// bursts, so this sits well above that and far below a delivery run of junk.
    /// </remarks>
    public int MaxInboundConnectionsPerHour { get; set; } = 120;

    /// <summary>
    /// Mail transactions one address may start in an hour without signing in, across every SMTP
    /// listener. Counted at <c>MAIL FROM</c>, whether or not a message is then accepted.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Higher than the connection allowance because a well-behaved exchanger reuses one
    /// connection for several messages, and penalising it for that would push senders towards
    /// the more expensive pattern.
    /// </para>
    /// <para>
    /// A signed-in session is charged to <see cref="MaxMessagesPerMailboxPerHour"/> instead, and
    /// never to this: every transaction draws on exactly one allowance.
    /// </para>
    /// </remarks>
    public int MaxInboundMessagesPerHour { get; set; } = 600;

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

    /// <summary>
    /// Longest IMAP command line accepted, excluding the terminator.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Deliberately far larger than <see cref="MaxSmtpLineBytes"/>. RFC 2683 §3.2.1.5 asks a
    /// server to allow "a command line of at least 8000 octets", against a client that should
    /// keep to about 1000 — the headroom exists because one IMAP command can legitimately carry
    /// a long argument that SMTP has no equivalent of.
    /// </para>
    /// <para>
    /// A sequence set is that argument. <see cref="Domain.Imap.ImapSequenceSet.MaxSegments"/>
    /// accepts ten thousand comma-separated segments, which cannot fit in four kilobytes; a
    /// client that enumerates messages individually rather than as a range — the exact case
    /// RFC 2683 §3.2.1.5 is written about — would otherwise hit the line limit long before the
    /// segment limit, and be refused for a command that was within every documented bound.
    /// </para>
    /// <para>
    /// This bounds command text only. A literal's octets are not part of the line and are
    /// governed by their own, much larger cap, decided where the literal is actually read —
    /// see <see cref="Domain.Imap.ImapLiteralSpecifier"/> on why a claimed byte count and the
    /// limit on it belong in different places.
    /// </para>
    /// </remarks>
    [Range(8_000, 262_144)]
    public int MaxImapLineBytes { get; set; } = 16_384;

    /// <summary>
    /// Longest an IMAP connection may sit idle before it has authenticated.
    /// </summary>
    /// <remarks>
    /// Short on purpose, and deliberately not governed by the thirty-minute floor below.
    /// RFC 3501 §5.4's autologout rule protects a <i>session</i> — a client that has logged in
    /// and has a mailbox open — from being dropped while a user is simply not looking at it. A
    /// connection that has sent nothing and proven nothing is not that; it is the slowloris
    /// case, where the cost of holding a connection open must stay far below the cost of
    /// opening one.
    /// </remarks>
    [Range(10, 600)]
    public int ImapPreAuthenticationTimeoutSeconds { get; set; } = 60;

    /// <summary>
    /// Longest an authenticated IMAP connection may sit idle before the server logs it out.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The lower bound of the range is a conformance requirement, not a preference.</b>
    /// RFC 3501 §5.4: "If a server has an inactivity autologout timer, the duration of that
    /// timer MUST be at least 30 minutes." Expressing that as the floor of the
    /// <see cref="RangeAttribute"/> rather than as a comment means an operator cannot configure
    /// this server into violating it — the options validator refuses to start instead.
    /// </para>
    /// <para>
    /// It is an <i>inactivity</i> timer and has no session-lifetime counterpart, which is the
    /// other half of §5.4: "The receipt of ANY command from the client during that interval
    /// SHOULD suffice to reset the autologout timer." An absolute cap on how long a connection
    /// may live — which the SMTP listener does have, and correctly, since an SMTP transaction is
    /// short by nature — would drop a client in the middle of a working session.
    /// </para>
    /// <para>
    /// RFC 2177 §3 is the client's side of the same number: a client using <c>IDLE</c> is
    /// advised to re-issue it "at least every 29 minutes to avoid being logged off", which is
    /// only sound advice if the server's timer is the thirty minutes this floor guarantees.
    /// </para>
    /// </remarks>
    [Range(1_800, 86_400)]
    public int ImapInactivityTimeoutSeconds { get; set; } = 1_800;

    /// <summary>
    /// Longest a POP3 connection may sit idle before it has authenticated.
    /// </summary>
    /// <remarks>
    /// Bounds slowloris. A POP3 client sends <c>USER</c> and <c>PASS</c> immediately, so this is
    /// far shorter than the authenticated timer and is not the one RFC 1939 §3 sets a floor for —
    /// that floor is about a session that has a maildrop open.
    /// </remarks>
    [Range(5, 600)]
    public int Pop3PreAuthenticationTimeoutSeconds { get; set; } = 60;

    /// <summary>
    /// Longest an authenticated POP3 connection may sit idle.
    /// </summary>
    /// <remarks>
    /// <b>The lower bound of the range is a conformance requirement, not a preference.</b>
    /// RFC 1939 §3: "A POP3 server MAY have an inactivity autologout timer. Such a timer MUST be
    /// of at least 10 minutes' duration." Expressing that as the floor of the
    /// <see cref="RangeAttribute"/> rather than as a comment means an operator cannot configure
    /// this server into violating it — the options validator refuses to start instead.
    /// </remarks>
    [Range(600, 86_400)]
    public int Pop3InactivityTimeoutSeconds { get; set; } = 600;

    /// <summary>
    /// Longest POP3 command line accepted.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>RFC 2449 §4 sets the conformance floor at 255</b>: "Servers which support the CAPA
    /// command MUST support commands up to 255 octets." This server supports CAPA, so no value
    /// below that would be conformant.
    /// </para>
    /// <para>
    /// <b>The range starts at 512 rather than 255 because the line reader's own floor is 512</b>
    /// — the same reader IMAP uses, which refuses to be constructed below it. A range that
    /// admitted 255 would let an operator configure a server whose every POP3 connection failed
    /// before its greeting, which is the worst kind of misconfiguration: silent, total, and
    /// indistinguishable from a firewall. Every value in this range satisfies §4 with room.
    /// </para>
    /// <para>
    /// The default leaves room for a long passphrase, which RFC 1939 §7 puts entirely in one
    /// argument: "a POP3 server may treat spaces in the argument as part of the password".
    /// </para>
    /// </remarks>
    [Range(512, 8_192)]
    public int MaxPop3LineBytes { get; set; } = 1_024;

    [Range(4_096, 4 * 1024 * 1024)]
    public int MaxHeaderBytes { get; set; } = 256 * 1024;

    /// <summary>Maximum MIME nesting depth. Bounds the MIME-bomb attack.</summary>
    [Range(1, 200)]
    public int MaxMimeDepth { get; set; } = 20;

    [Range(1, 20)]
    public int MaxAuthAttemptsPerSession { get; set; } = 3;

    /// <summary>
    /// Messages one authenticated mailbox may submit per hour.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The bound on what a stolen password is worth. An attacker with valid credentials passes
    /// every downstream check — SPF, DKIM, DMARC all say the mail is genuine, because it is —
    /// so the only thing standing between a compromised account and a domain's reputation is how
    /// much it can send before anyone notices.
    /// </para>
    /// <para>
    /// The default is generous for a person and restrictive for a script. An organisation with a
    /// legitimate bulk sender should give that sender its own mailbox and raise this for it,
    /// rather than raising it for everyone.
    /// </para>
    /// </remarks>
    [Range(1, 100_000)]
    public int MaxMessagesPerMailboxPerHour { get; set; } = 200;
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

/// <summary>
/// Collecting the RFC 8460 TLS reports other senders deliver.
/// </summary>
/// <remarks>
/// <para>
/// <b>Off by default, because it needs a mailbox that exists.</b> §3 has senders deliver reports
/// to the address in the <c>_smtp._tls</c> record, so collection only makes sense once that
/// address is published and has a mailbox here to deliver into. Turning it on before then would
/// log a warning every pass about a mailbox nobody created.
/// </para>
/// <para>
/// <b>Reading only.</b> The collector never marks, moves or deletes anything in that mailbox —
/// a human may be reading the same folder — so pointing it at a mailbox somebody uses is safe.
/// </para>
/// </remarks>
public sealed class TlsRptOptions
{
    /// <summary>Whether to collect reports at all.</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// The address reports are delivered to — the one in the <c>_smtp._tls</c> record's
    /// <c>rua=mailto:</c>.
    /// </summary>
    /// <remarks>
    /// A mailbox on this server. The report is filed under <i>this</i> address's domain rather
    /// than under the policy-domain the sender wrote, because a report is about the domain whose
    /// reporting address received it — taking the sender's word would let anyone who can reach
    /// the address file a report against any domain this server hosts.
    /// </remarks>
    public string ReportMailbox { get; set; } = string.Empty;

    /// <summary>
    /// How often to look, in minutes. Six hours by default.
    /// </summary>
    /// <remarks>
    /// Reports are aggregate and daily — §3 has senders send at most one per day per domain — so
    /// polling often buys nothing and costs a mailbox scan. Six hours means a report is picked
    /// up the same day it arrives without the collector running on anybody's idea of a busy
    /// loop.
    /// </remarks>
    [Range(5, 1440)]
    public int PollMinutes { get; set; } = 360;
}
