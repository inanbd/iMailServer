using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Persistence;
using MailServer.Infrastructure.Persistence.Queries;
using MailServer.Infrastructure.Persistence.Repositories;
using MailServer.Infrastructure.Time;
using MailServer.Persistence.Sqlite;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MailServer.Persistence.Tests;

/// <summary>
/// A real, file-backed SQLite database for one test.
/// </summary>
/// <remarks>
/// <para>
/// <b>File-backed, not in-memory.</b> An in-memory SQLite database behaves differently in
/// exactly the ways these tests exist to check: WAL is unavailable, the locking model
/// differs, and connection pooling interacts with it strangely. Testing persistence against
/// a database that does not behave like the production one proves nothing about production.
/// </para>
/// <para>
/// Each instance gets its own file in the temp directory and deletes it on dispose.
/// </para>
/// </remarks>
public sealed class SqliteTestDatabase : IAsyncDisposable
{
    private readonly string _directory;

    public SqliteTestDatabase()
    {
        _directory = Path.Combine(Path.GetTempPath(), "aethermail-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);

        DatabasePath = Path.Combine(_directory, "test.db");

        MailServerOptions options = new()
        {
            Database = new DatabaseOptions
            {
                Provider = DatabaseProvider.Sqlite,
                Sqlite = new SqliteOptions
                {
                    DataSource = DatabasePath,
                    BusyTimeoutMs = 5_000,
                    JournalMode = "WAL",
                    Synchronous = "NORMAL",
                },
            },
            Storage = new StorageOptions { DataRoot = _directory },
        };

        Options = Microsoft.Extensions.Options.Options.Create(options);
        Dialect = new SqliteDialect();
        Clock = new SystemClock();

        ConnectionFactory = new SqliteConnectionFactory(
            Options,
            NullLogger<SqliteConnectionFactory>.Instance);

        // Dapper's type-handler table is process-global. The production code initialises it
        // in AddInfrastructure; the tests bypass DI, so they must do it explicitly.
        DapperConfiguration.Initialize();

        WriteGate = new SqlWriteGate(Dialect, NullLogger<SqlWriteGate>.Instance);
    }

    public string DatabasePath { get; }

    public IOptions<MailServerOptions> Options { get; }

    public ISqlDialect Dialect { get; }

    public SystemClock Clock { get; }

    public IDbConnectionFactory ConnectionFactory { get; }

    public SqlWriteGate WriteGate { get; }

    /// <summary>Applies every migration, leaving the database at the current schema version.</summary>
    public async Task<MigrationRunResult> MigrateAsync(CancellationToken cancellationToken = default) =>
        await CreateMigrator().MigrateAsync(cancellationToken);

    public IDatabaseMigrator CreateMigrator() =>
        new MigrationRunner(
            ConnectionFactory,
            Dialect,
            Clock,
            new TestEnvironmentInfo(),
            Options,
            NullLogger<MigrationRunner>.Instance);

    /// <summary>Creates a fresh scope's worth of persistence services.</summary>
    /// <remarks>
    /// Mirrors what the DI container builds per request: one ambient-session holder, one
    /// transaction manager, and repositories that share them.
    /// </remarks>
    public TestScope CreateScope() => new(this);

    public async ValueTask DisposeAsync()
    {
        WriteGate.Dispose();

        // SQLite pools connections, and the pool holds the file open on Windows. Clearing it
        // is what makes the directory deletable.
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

        await Task.Yield();

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

    /// <summary>The persistence services one logical request would resolve.</summary>
    public sealed class TestScope
    {
        internal TestScope(SqliteTestDatabase database)
        {
            AmbientSession = new AmbientDbSession();

            Transactions = new TransactionManager(
                database.ConnectionFactory,
                AmbientSession,
                database.Dialect,
                database.WriteGate,
                NullLogger<TransactionManager>.Instance);

            Domains = new DomainRepository(
                database.ConnectionFactory,
                AmbientSession,
                database.Dialect);

            Audit = new AuditRepository(
                database.ConnectionFactory,
                AmbientSession,
                database.Dialect);

            DomainQueries = new DomainQueries(
                database.ConnectionFactory,
                AmbientSession,
                database.Dialect);

            StatusQueries = new ServerStatusQueries(
                database.ConnectionFactory,
                AmbientSession,
                database.Dialect);

            Outbound = new OutboundQueueRepository(
                database.ConnectionFactory,
                AmbientSession,
                database.Dialect);

            Deliveries = new DeliveryRepository(
                database.ConnectionFactory,
                AmbientSession,
                database.Dialect);

            ImapMailboxes = new ImapMailboxReader(
                database.ConnectionFactory,
                AmbientSession,
                database.Dialect);

            // Given the real reader and the real transaction manager, because what the writer is
            // for is applying a store and reading back what it wrote in one transaction - and a
            // substitute for either would leave that untested.
            ImapWrites = new ImapMailboxWriter(
                database.ConnectionFactory,
                AmbientSession,
                database.Dialect,
                Transactions,
                ImapMailboxes);
        }

        internal AmbientDbSession AmbientSession { get; }

        public ITransactionManager Transactions { get; }

        public IDomainRepository Domains { get; }

        public IAuditRepository Audit { get; }

        public Application.Abstractions.Queries.IDomainQueries DomainQueries { get; }

        public Application.Abstractions.Queries.IServerStatusQueries StatusQueries { get; }

        public IOutboundQueueRepository Outbound { get; }

        public IDeliveryRepository Deliveries { get; }

        public IImapMailboxReader ImapMailboxes { get; }

        public IImapMailboxWriter ImapWrites { get; }
    }
}

/// <summary>Deterministic environment facts for tests.</summary>
internal sealed class TestEnvironmentInfo : IEnvironmentInfo
{
    public string MachineName => "TEST-MACHINE";

    public string ProcessAccount => "TEST-ACCOUNT";

    public string OperatingSystem => "Test OS";

    public string RuntimeVersion => "Test Runtime";

    public string ProductVersion => "0.1.0-test";

    public bool IsWindows => OperatingSystemIsWindows;

    public bool IsWindowsService => false;

    public long GetAvailableFreeSpaceBytes(string path) => long.MaxValue;

    private static bool OperatingSystemIsWindows => System.OperatingSystem.IsWindows();
}
