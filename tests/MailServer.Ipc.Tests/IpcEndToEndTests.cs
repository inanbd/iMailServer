using System.IO.Pipes;
using MailServer.Application;
using MailServer.Application.Abstractions.Certificates;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Common;
using MailServer.Application.Smtp.Queries;
using MailServer.Application.Smtp.Dtos;
using MailServer.Application.Abstractions.Smtp;
using MailServer.Application.Domains.Commands;
using MailServer.Application.Domains.Dtos;
using MailServer.Application.Domains.Queries;
using MailServer.Application.Security.Dtos;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Ipc.Protocol;
using MailServer.Ipc.Server;
using MailServer.Ipc.Tests.Doubles;
using MailServer.Infrastructure.Security;
using MediatR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Ipc.Tests;

/// <summary>
/// Drives a real named pipe, real framing, the real MediatR pipeline and real handlers.
/// </summary>
/// <remarks>
/// <para>
/// The only substitutions are the database (an in-memory repository) and the clock. Everything
/// the IPC layer exists to do - framing, version negotiation, registry lookup, identity
/// assignment, authorization, validation, error mapping - runs for real.
/// </para>
/// <para>
/// .NET implements named pipes over Unix domain sockets on non-Windows platforms, so this
/// exercises the same transport code that runs on Windows. What it cannot exercise is the
/// Windows ACL, which is why <c>IpcPipeSecurity</c> logs loudly when it is skipped and why
/// Windows CI is a stated prerequisite from Milestone 2.
/// </para>
/// </remarks>
public sealed class IpcEndToEndTests : IAsyncLifetime
{
    private readonly string _pipeName = $"aethermail-test-{Guid.NewGuid():N}";
    private ServiceProvider _services = null!;
    private IpcRequestDispatcher _dispatcher = null!;
    private IAdminSessionManager _sessions = null!;
    private string _sessionToken = null!;
    private FakeDomainRepository _domains = null!;
    private CancellationTokenSource _serverCancellation = null!;
    private Task _serverLoop = null!;

    public Task InitializeAsync()
    {
        _domains = new FakeDomainRepository();

        ServiceCollection services = new();

        services.AddLogging();
        services.AddApplication();

        services.AddSingleton<IClock>(new FixedClock());
        services.AddSingleton<IDomainRepository>(_domains);
        services.AddSingleton<IDomainQueries>(new FakeDomainQueries(_domains));
        services.AddSingleton<IServerStatusQueries, FakeServerStatusQueries>();
        services.AddSingleton<IHealthRegistry, FakeHealthRegistry>();
        services.AddSingleton<IMaintenanceModeAccessor, FakeMaintenanceMode>();
        services.AddSingleton<IEnvironmentInfo, FakeEnvironmentInfo>();
        services.AddSingleton<IServerIdentityProvider, FakeServerIdentity>();
        services.AddSingleton<ISqlDialect, FakeSqlDialect>();
        services.AddSingleton<ISmtpQueries, FakeSmtpQueries>();
        services.AddSingleton<ISmtpConfigurationView, FakeSmtpConfigurationView>();

        // Scoped, exactly as the real container registers them: one identity and one
        // correlation id per request.
        services.AddScoped<ScopedAdminContext>();
        services.AddScoped<IAdminContext>(sp => sp.GetRequiredService<ScopedAdminContext>());
        services.AddScoped<IAdminContextInitializer>(sp => sp.GetRequiredService<ScopedAdminContext>());
        services.AddScoped<ICorrelationContext, ScopedCorrelationContext>();
        services.AddScoped<IAuditTrail, RecordingAuditTrail>();

        // A real session manager, so the dispatcher's session enforcement is exercised rather
        // than stubbed - that enforcement is the point of these tests from Milestone 2 on.
        services.AddSingleton<ISecuritySettings>(new FakeSecuritySettings());
        services.AddSingleton<IAdminAccountRepository, EmptyAdminAccountRepository>();
        services.AddSingleton<IAdminSessionManager, AdminSessionManager>();
        services.AddScoped<ISecurityEventRecorder, RecordingSecurityEventRecorder>();

        // No transaction manager is registered because nothing in these tests is marked
        // transactional at the persistence level; TransactionBehavior resolves it lazily.
        services.AddScoped<ITlsReloadCoordinator, RecordingTlsReloadCoordinator>();

        services.AddScoped<ITransactionManager, PassThroughTransactionManager>();

        _services = services.BuildServiceProvider();

        _sessions = _services.GetRequiredService<IAdminSessionManager>();

        _dispatcher = new IpcRequestDispatcher(
            _services.GetRequiredService<IServiceScopeFactory>(),
            new IpcCommandRegistry(),
            _sessions,
            NullLogger<IpcRequestDispatcher>.Instance);

        // A session issued directly, rather than through the sign-in command, so these tests
        // stay focused on the transport and dispatch layers. The full authentication flow is
        // covered end to end in MailServer.SecurityTests.
        (AdminSession _, string token) = _sessions
            .CreateAsync(
                "test-admin",
                AdminPermission.FullControl,
                "test",
                mustChangePassword: false,
                CancellationToken.None)
            .GetAwaiter()
            .GetResult();

        _sessionToken = token;

        _serverCancellation = new CancellationTokenSource();
        _serverLoop = RunServerAsync(_serverCancellation.Token);

        return Task.CompletedTask;
    }

    public async Task DisposeAsync()
    {
        await _serverCancellation.CancelAsync();

        try
        {
            await _serverLoop;
        }
        catch (OperationCanceledException)
        {
            // Expected on shutdown.
        }

        _serverCancellation.Dispose();
        await _services.DisposeAsync();
    }

    /// <summary>A minimal accept loop using the production framing and dispatcher.</summary>
    private async Task RunServerAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await using NamedPipeServerStream pipe = new(
                _pipeName,
                PipeDirection.InOut,
                4,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous);

            try
            {
                await pipe.WaitForConnectionAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            IpcCallerIdentity caller = new("test-admin", "test-session", AdminPermission.FullControl);

            try
            {
                while (pipe.IsConnected && !cancellationToken.IsCancellationRequested)
                {
                    IpcRequest? request = await IpcFrame
                        .ReadAsync<IpcRequest>(pipe, 1024 * 1024, cancellationToken);

                    if (request is null)
                    {
                        break;
                    }

                    IpcResponse response =
                        await _dispatcher.DispatchAsync(request, caller, cancellationToken);

                    await IpcFrame.WriteAsync(pipe, response, 1024 * 1024, cancellationToken);
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (IOException)
            {
                // The client went away mid-conversation; accept the next connection.
            }
        }
    }

    private async Task<IpcResponse> SendAsync(
        string command,
        object payload,
        int protocolVersion = IpcProtocol.Version,
        string? sessionToken = null,
        bool omitSessionToken = false)
    {
        IpcRequest request = new()
        {
            ProtocolVersion = protocolVersion,
            RequestId = Guid.NewGuid().ToString("N"),
            Command = command,
            Payload = IpcFrame.SerializePayload(payload),
            CorrelationId = "test-correlation",
            SessionToken = omitSessionToken ? null : sessionToken ?? _sessionToken,
        };

        // Connect-and-exchange is retried because of a quirk of the harness, not of the
        // protocol. This accept loop serves one connection at a time, so between requests there
        // is a moment when the previous NamedPipeServerStream is being retired and its
        // replacement is not yet listening. On Unix, where .NET implements named pipes over
        // domain sockets, a client can connect into that dying listener's backlog and then see
        // the connection reset on its first read. The real service keeps several server
        // instances open concurrently and does not have the gap; treating it as fatal here
        // would make an unrelated harness detail look like a protocol defect.
        IOException? lastFailure = null;

        for (int attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                await using NamedPipeClientStream client = new(
                    ".",
                    _pipeName,
                    PipeDirection.InOut,
                    PipeOptions.Asynchronous);

                await client.ConnectAsync(10_000, CancellationToken.None);

                await IpcFrame.WriteAsync(client, request, 1024 * 1024, CancellationToken.None);

                IpcResponse? response = await IpcFrame
                    .ReadAsync<IpcResponse>(client, 1024 * 1024, CancellationToken.None);

                if (response is null)
                {
                    lastFailure = new IOException("The server closed the pipe without replying.");
                    continue;
                }

                response.RequestId.ShouldBe(request.RequestId);

                return response;
            }
            catch (IOException ex)
            {
                lastFailure = ex;
                await Task.Delay(20, CancellationToken.None);
            }
        }

        throw new IOException(
            $"Could not complete '{command}' over the test pipe after 5 attempts.", lastFailure);
    }

    [Fact]
    public async Task A_domain_can_be_created_over_the_pipe()
    {
        IpcResponse response = await SendAsync(
            "Domains.Create",
            new CreateDomainCommand { Name = "example.com", MailHostname = "mail.example.com" });

        response.Success.ShouldBeTrue();

        DomainSummaryDto? created = IpcFrame.DeserializePayload<DomainSummaryDto>(response.Payload);

        created.ShouldNotBeNull();
        created.Name.ShouldBe("example.com");
        created.Status.ShouldBe(DomainStatus.Pending);

        _domains.All.ShouldHaveSingleItem().Name.Value.ShouldBe("example.com");
    }

    [Fact]
    public async Task A_created_domain_is_visible_to_a_subsequent_query()
    {
        await SendAsync("Domains.Create", new CreateDomainCommand { Name = "alpha.example" });
        await SendAsync("Domains.Create", new CreateDomainCommand { Name = "beta.example" });

        IpcResponse response = await SendAsync("Domains.List", new GetDomainsQuery());

        response.Success.ShouldBeTrue();

        PagedResult<DomainSummaryDto>? page =
            IpcFrame.DeserializePayload<PagedResult<DomainSummaryDto>>(response.Payload);

        page.ShouldNotBeNull();
        page.Items.Count.ShouldBe(2);
    }

    [Fact]
    public async Task The_smtp_status_crosses_the_pipe()
    {
        // Milestone 6 adds two IPC commands. Registering one without a working round trip is how
        // the admin app ends up showing an empty screen with no error.
        IpcResponse response = await SendAsync("Smtp.Status", new GetSmtpStatusQuery());

        response.Success.ShouldBeTrue();

        SmtpStatusDto? status = IpcFrame.DeserializePayload<SmtpStatusDto>(response.Payload);

        status.ShouldNotBeNull();
        status.Listeners.Count.ShouldBe(3);
        status.Listeners.ShouldContain(l => l.Role == SmtpListenerRole.InboundMta && l.Port == 25);

        // The MTA listener never offers AUTH, and the status screen must say so rather than
        // leaving an operator to assume it does.
        status.Listeners
            .Single(l => l.Role == SmtpListenerRole.InboundMta)
            .OffersAuthentication.ShouldBeFalse();
    }

    [Fact]
    public async Task The_received_mail_log_crosses_the_pipe()
    {
        IpcResponse response = await SendAsync(
            "Smtp.Received",
            new GetReceivedMessagesQuery { PageSize = 10 });

        response.Success.ShouldBeTrue();

        PagedResult<ReceivedMessageDto>? page =
            IpcFrame.DeserializePayload<PagedResult<ReceivedMessageDto>>(response.Payload);

        page.ShouldNotBeNull();
        page.Items.ShouldHaveSingleItem().ReversePath.ShouldBe("sender@example.net");
    }

    [Fact]
    public void No_ipc_command_returns_message_content()
    {
        // The administration app cannot read customers' mail because there is no command that
        // would let it. Asserted over the registry rather than trusted, so adding one is a
        // deliberate act that fails here.
        IpcCommandRegistry registry = new();

        foreach (IpcCommandDescriptor descriptor in registry.Commands)
        {
            string response = descriptor.ResponseType.FullName ?? string.Empty;

            response.ShouldNotContain("Stream", Case.Insensitive);
            response.ShouldNotContain("System.Byte[]");
        }
    }

    [Fact]
    public async Task The_correlation_id_survives_the_round_trip()
    {
        // One operation must be traceable across both processes; otherwise the admin
        // application's error message and the service's log entry cannot be joined.
        IpcResponse response = await SendAsync(
            "Domains.Create",
            new CreateDomainCommand { Name = "correlated.example" });

        response.CorrelationId.ShouldBe("test-correlation");
    }

    [Fact]
    public async Task An_unknown_command_is_refused_without_reaching_a_handler()
    {
        IpcResponse response = await SendAsync(
            "System.Diagnostics.Process.Start",
            new { anything = "at all" });

        response.Success.ShouldBeFalse();
        response.Error!.Kind.ShouldBe(IpcErrorKind.UnknownCommand);
        response.Error.Code.ShouldBe("ipc.unknown_command");
    }

    [Fact]
    public async Task A_mismatched_protocol_version_is_refused_with_an_actionable_message()
    {
        IpcResponse response = await SendAsync(
            "Domains.List",
            new GetDomainsQuery(),
            protocolVersion: IpcProtocol.Version + 99);

        response.Success.ShouldBeFalse();
        response.Error!.Kind.ShouldBe(IpcErrorKind.ProtocolMismatch);
        response.Error.Message.ShouldContain("Upgrade the administration application");
    }

    [Fact]
    public async Task A_validation_failure_crosses_the_wire_with_per_field_detail()
    {
        IpcResponse response = await SendAsync(
            "Domains.Create",
            new CreateDomainCommand { Name = "not a valid domain" });

        response.Success.ShouldBeFalse();
        response.Error!.Kind.ShouldBe(IpcErrorKind.Validation);

        // Per-field detail is what lets the UI highlight the offending control rather than
        // showing one opaque message.
        response.Error.ValidationErrors.ShouldNotBeNull();
        response.Error.ValidationErrors.ShouldContainKey(nameof(CreateDomainCommand.Name));
    }

    [Fact]
    public async Task A_duplicate_domain_is_reported_as_a_conflict()
    {
        await SendAsync("Domains.Create", new CreateDomainCommand { Name = "duplicate.example" });

        IpcResponse response = await SendAsync(
            "Domains.Create",
            new CreateDomainCommand { Name = "duplicate.example" });

        response.Success.ShouldBeFalse();
        response.Error!.Kind.ShouldBe(IpcErrorKind.Conflict);
    }

    [Fact]
    public async Task A_domain_rule_violation_crosses_the_wire_with_its_explanation()
    {
        IpcResponse created = await SendAsync(
            "Domains.Create",
            new CreateDomainCommand { Name = "nohostname.example" });

        DomainSummaryDto domain =
            IpcFrame.DeserializePayload<DomainSummaryDto>(created.Payload)!;

        IpcResponse response = await SendAsync(
            "Domains.SetStatus",
            new SetDomainStatusCommand { DomainId = domain.Id, Enabled = true });

        response.Success.ShouldBeFalse();
        response.Error!.Kind.ShouldBe(IpcErrorKind.DomainRule);
        response.Error.Code.ShouldBe("domain.enable.no_hostname");

        // The message was written for an administrator to read, so it travels verbatim.
        response.Error.Message.ShouldContain("outbound identity");
    }

    [Fact]
    public async Task A_missing_target_is_reported_as_not_found()
    {
        IpcResponse response = await SendAsync(
            "Domains.Get",
            new GetDomainDetailsQuery { DomainId = Guid.NewGuid() });

        response.Success.ShouldBeFalse();
        response.Error!.Kind.ShouldBe(IpcErrorKind.NotFound);
    }

    [Fact]
    public async Task Several_requests_reuse_one_connection_in_order()
    {
        await using NamedPipeClientStream client = new(
            ".",
            _pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);

        await client.ConnectAsync(10_000, CancellationToken.None);

        for (int i = 0; i < 5; i++)
        {
            IpcRequest request = new()
            {
                ProtocolVersion = IpcProtocol.Version,
                RequestId = $"req-{i}",
                Command = "Domains.Create",
                Payload = IpcFrame.SerializePayload(
                    new CreateDomainCommand { Name = $"d{i}.example" }),
                CorrelationId = "test-correlation",
                SessionToken = _sessionToken,
            };

            await IpcFrame.WriteAsync(client, request, 1024 * 1024, CancellationToken.None);

            IpcResponse? response =
                await IpcFrame.ReadAsync<IpcResponse>(client, 1024 * 1024, CancellationToken.None);

            // Request/response pairing on a shared connection: a mismatch here would mean one
            // caller receiving another caller's data.
            response!.RequestId.ShouldBe($"req-{i}");
            response.Success.ShouldBeTrue();
        }

        _domains.All.Count.ShouldBe(5);
    }

    // ---- Session enforcement -------------------------------------------------------------
    //
    // Protocol v2's central security property: a Windows identity that can open the pipe is
    // necessary but no longer sufficient. Every administrative command needs a session token
    // issued by a successful sign-in, and exactly four commands do not.

    public static TheoryData<string> SessionRequiredCommands
    {
        get
        {
            TheoryData<string> data = [];

            foreach (IpcCommandDescriptor descriptor in new IpcCommandRegistry().Commands)
            {
                if (descriptor.RequiresSession)
                {
                    data.Add(descriptor.Name);
                }
            }

            return data;
        }
    }

    public static TheoryData<string> AnonymousCommands
    {
        get
        {
            TheoryData<string> data = [];

            foreach (IpcCommandDescriptor descriptor in new IpcCommandRegistry().Commands)
            {
                if (!descriptor.RequiresSession)
                {
                    data.Add(descriptor.Name);
                }
            }

            return data;
        }
    }

    /// <summary>
    /// Driven from the registry rather than a hand-written list, so a command added in a later
    /// milestone is covered the moment it is registered.
    /// </summary>
    [Theory]
    [MemberData(nameof(SessionRequiredCommands))]
    public async Task Every_session_required_command_is_refused_without_a_token(string command)
    {
        IpcResponse response = await SendAsync(command, new { }, omitSessionToken: true);

        response.Success.ShouldBeFalse();
        response.Error.ShouldNotBeNull();
        response.Error!.Kind.ShouldBe(IpcErrorKind.Unauthenticated);
    }

    [Theory]
    [MemberData(nameof(SessionRequiredCommands))]
    public async Task Every_session_required_command_is_refused_with_a_forged_token(string command)
    {
        // 32 bytes of the right shape but never issued: the manager stores hashes of tokens it
        // created, so a structurally valid token it has not seen must not validate.
        string forged = Convert.ToBase64String(
            Enumerable.Range(0, 32).Select(static i => (byte)i).ToArray());

        IpcResponse response = await SendAsync(command, new { }, sessionToken: forged);

        response.Success.ShouldBeFalse();
        response.Error.ShouldNotBeNull();
        response.Error!.Kind.ShouldBe(IpcErrorKind.Unauthenticated);
    }

    [Theory]
    [MemberData(nameof(AnonymousCommands))]
    public async Task An_anonymous_command_is_not_refused_for_want_of_a_session(string command)
    {
        IpcResponse response = await SendAsync(command, new { }, omitSessionToken: true);

        // The payloads here are empty, so most of these fail validation - which is the point.
        // Reaching validation means the session gate let them through.
        if (!response.Success)
        {
            response.Error.ShouldNotBeNull();
            response.Error!.Kind.ShouldNotBe(IpcErrorKind.Unauthenticated);
        }
    }

    [Fact]
    public async Task Setup_status_is_readable_before_sign_in()
    {
        IpcResponse response = await SendAsync(
            "Security.SetupStatus",
            new { },
            omitSessionToken: true);

        response.Success.ShouldBeTrue();

        SetupStatusDto status = IpcFrame.DeserializePayload<SetupStatusDto>(response.Payload)!;

        status.RequiresSetup.ShouldBeTrue();
        status.IsLockedOut.ShouldBeFalse();
    }

    [Fact]
    public async Task A_revoked_session_stops_working_immediately()
    {
        (AdminSession session, string token) = await _sessions.CreateAsync(
            "revocation-test",
            AdminPermission.FullControl,
            "test",
            mustChangePassword: false,
            CancellationToken.None);

        IpcResponse before = await SendAsync("Domains.List", new { }, sessionToken: token);
        before.Success.ShouldBeTrue();

        await _sessions.RevokeAsync(session.Id, CancellationToken.None);

        IpcResponse after = await SendAsync("Domains.List", new { }, sessionToken: token);

        after.Success.ShouldBeFalse();
        after.Error!.Kind.ShouldBe(IpcErrorKind.Unauthenticated);
    }

    /// <summary>
    /// The refusal must not distinguish "no such session" from "expired" or "revoked": that
    /// distinction is useful only to somebody probing, and it is recorded in the log instead.
    /// </summary>
    [Fact]
    public async Task Refusals_do_not_reveal_why_the_session_was_rejected()
    {
        IpcResponse missing = await SendAsync("Domains.List", new { }, omitSessionToken: true);
        IpcResponse forged = await SendAsync("Domains.List", new { }, sessionToken: "not-a-token");

        missing.Error!.Code.ShouldBe(forged.Error!.Code);
        missing.Error!.Message.ShouldBe(forged.Error!.Message);
    }
}
