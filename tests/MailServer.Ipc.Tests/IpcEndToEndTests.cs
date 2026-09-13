using System.IO.Pipes;
using MailServer.Application;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Security;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Common;
using MailServer.Application.Domains.Commands;
using MailServer.Application.Domains.Dtos;
using MailServer.Application.Domains.Queries;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MailServer.Ipc.Protocol;
using MailServer.Ipc.Server;
using MailServer.Ipc.Tests.Doubles;
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

        // Scoped, exactly as the real container registers them: one identity and one
        // correlation id per request.
        services.AddScoped<ScopedAdminContext>();
        services.AddScoped<IAdminContext>(sp => sp.GetRequiredService<ScopedAdminContext>());
        services.AddScoped<IAdminContextInitializer>(sp => sp.GetRequiredService<ScopedAdminContext>());
        services.AddScoped<ICorrelationContext, ScopedCorrelationContext>();
        services.AddScoped<IAuditTrail, RecordingAuditTrail>();

        // No transaction manager is registered because nothing in these tests is marked
        // transactional at the persistence level; TransactionBehavior resolves it lazily.
        services.AddScoped<ITransactionManager, PassThroughTransactionManager>();

        _services = services.BuildServiceProvider();

        _dispatcher = new IpcRequestDispatcher(
            _services.GetRequiredService<IServiceScopeFactory>(),
            new IpcCommandRegistry(),
            NullLogger<IpcRequestDispatcher>.Instance);

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
        int protocolVersion = IpcProtocol.Version)
    {
        await using NamedPipeClientStream client = new(
            ".",
            _pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);

        await client.ConnectAsync(10_000, CancellationToken.None);

        IpcRequest request = new()
        {
            ProtocolVersion = protocolVersion,
            RequestId = Guid.NewGuid().ToString("N"),
            Command = command,
            Payload = IpcFrame.SerializePayload(payload),
            CorrelationId = "test-correlation",
        };

        await IpcFrame.WriteAsync(client, request, 1024 * 1024, CancellationToken.None);

        IpcResponse? response =
            await IpcFrame.ReadAsync<IpcResponse>(client, 1024 * 1024, CancellationToken.None);

        response.ShouldNotBeNull();
        response.RequestId.ShouldBe(request.RequestId);

        return response;
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
}
