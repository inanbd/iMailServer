using FluentValidation;
using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Behaviors;
using MailServer.Application.Exceptions;
using MailServer.Application.Tests.Fakes;
using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Application.Tests.Behaviors;

public sealed class AuthorizationBehaviorTests
{
    private sealed record ProtectedCommand : ICommand<Unit>, IAuthorizedRequest, IAuditableRequest
    {
        public AdminPermission RequiredPermission => AdminPermission.ManageDomains;

        public AuditDescriptor DescribeForAudit() => new("Test.Protected", "Test", "target");
    }

    private sealed record ProtectedWrite
        : ICommand<Unit>, IAuthorizedRequest, ITransactionalRequest, IAuditableRequest
    {
        public AdminPermission RequiredPermission => AdminPermission.ManageDomains;

        public AuditDescriptor DescribeForAudit() => new("Test.Write", "Test", "target");
    }

    private static AuthorizationBehavior<TRequest, Unit> CreateBehavior<TRequest>(
        FakeAdminContext admin,
        FakeAuditTrail audit,
        FakeMaintenanceMode? maintenance = null)
        where TRequest : notnull =>
        new(admin,
            maintenance ?? new FakeMaintenanceMode(),
            audit,
            NullLogger<AuthorizationBehavior<TRequest, Unit>>.Instance);

    [Fact]
    public async Task A_caller_holding_the_permission_is_allowed_through()
    {
        FakeAuditTrail audit = new();
        AuthorizationBehavior<ProtectedCommand, Unit> behavior =
            CreateBehavior<ProtectedCommand>(new FakeAdminContext(AdminPermission.ManageDomains), audit);

        bool handlerRan = false;

        await behavior.Handle(
            new ProtectedCommand(),
            _ => { handlerRan = true; return Task.FromResult(Unit.Value); },
            CancellationToken.None);

        handlerRan.ShouldBeTrue();
        audit.Deferred.ShouldBeEmpty();
    }

    [Fact]
    public async Task A_caller_lacking_the_permission_is_denied_before_the_handler_runs()
    {
        FakeAuditTrail audit = new();
        AuthorizationBehavior<ProtectedCommand, Unit> behavior =
            CreateBehavior<ProtectedCommand>(new FakeAdminContext(AdminPermission.ViewServerState), audit);

        bool handlerRan = false;

        AuthorizationFailedException ex = await Should.ThrowAsync<AuthorizationFailedException>(
            () => behavior.Handle(
                new ProtectedCommand(),
                _ => { handlerRan = true; return Task.FromResult(Unit.Value); },
                CancellationToken.None));

        ex.RequiredPermission.ShouldBe(AdminPermission.ManageDomains);

        // The handler must never run. Authorization that happens after the work is not
        // authorization.
        handlerRan.ShouldBeFalse();
    }

    [Fact]
    public async Task An_unauthenticated_caller_is_denied_even_with_full_permissions()
    {
        // Defence against a bug in the IPC layer: if identity assignment is ever skipped, the
        // context stays unauthenticated and every request is denied rather than permitted.
        FakeAuditTrail audit = new();
        AuthorizationBehavior<ProtectedCommand, Unit> behavior = CreateBehavior<ProtectedCommand>(
            new FakeAdminContext(AdminPermission.FullControl, isAuthenticated: false),
            audit);

        await Should.ThrowAsync<AuthorizationFailedException>(
            () => behavior.Handle(
                new ProtectedCommand(),
                _ => Task.FromResult(Unit.Value),
                CancellationToken.None));
    }

    [Fact]
    public async Task A_denial_is_audited_as_deferred()
    {
        FakeAuditTrail audit = new();
        AuthorizationBehavior<ProtectedCommand, Unit> behavior =
            CreateBehavior<ProtectedCommand>(new FakeAdminContext(AdminPermission.None), audit);

        await Should.ThrowAsync<AuthorizationFailedException>(
            () => behavior.Handle(
                new ProtectedCommand(),
                _ => Task.FromResult(Unit.Value),
                CancellationToken.None));

        // Deferred, not immediate: a denial never reaches the audit stage because it throws
        // first, and there is no transaction to enlist in at this point anyway.
        audit.Deferred.ShouldHaveSingleItem().Result.ShouldBe(AuditResult.Denied);
        audit.Recorded.ShouldBeEmpty();
    }

    [Fact]
    public async Task A_write_is_refused_while_the_server_is_read_only()
    {
        FakeAuditTrail audit = new();
        AuthorizationBehavior<ProtectedWrite, Unit> behavior = CreateBehavior<ProtectedWrite>(
            new FakeAdminContext(AdminPermission.FullControl),
            audit,
            new FakeMaintenanceMode(MaintenanceMode.ReadOnly));

        MaintenanceModeException ex = await Should.ThrowAsync<MaintenanceModeException>(
            () => behavior.Handle(
                new ProtectedWrite(),
                _ => Task.FromResult(Unit.Value),
                CancellationToken.None));

        ex.Mode.ShouldBe(MaintenanceMode.ReadOnly);
    }

    [Fact]
    public async Task A_read_is_still_permitted_while_the_server_is_read_only()
    {
        // Queries are unaffected by read-only mode, so an operator can still see what is
        // happening while a restore or a provider migration runs.
        FakeAuditTrail audit = new();
        AuthorizationBehavior<ProtectedCommand, Unit> behavior = CreateBehavior<ProtectedCommand>(
            new FakeAdminContext(AdminPermission.FullControl),
            audit,
            new FakeMaintenanceMode(MaintenanceMode.ReadOnly));

        bool handlerRan = false;

        await behavior.Handle(
            new ProtectedCommand(),
            _ => { handlerRan = true; return Task.FromResult(Unit.Value); },
            CancellationToken.None);

        handlerRan.ShouldBeTrue();
    }
}

public sealed class ValidationBehaviorTests
{
    private sealed record SampleCommand(string Name) : ICommand<Unit>;

    private sealed class SampleValidator : AbstractValidator<SampleCommand>
    {
        public SampleValidator()
        {
            RuleFor(x => x.Name).NotEmpty().WithMessage("A name is required.");
            RuleFor(x => x.Name).MaximumLength(5).WithMessage("Too long.");
        }
    }

    [Fact]
    public async Task A_valid_request_reaches_the_handler()
    {
        ValidationBehavior<SampleCommand, Unit> behavior = new([new SampleValidator()]);

        bool handlerRan = false;

        await behavior.Handle(
            new SampleCommand("ok"),
            _ => { handlerRan = true; return Task.FromResult(Unit.Value); },
            CancellationToken.None);

        handlerRan.ShouldBeTrue();
    }

    [Fact]
    public async Task Every_failure_is_reported_at_once_rather_than_only_the_first()
    {
        // Returning one error at a time makes a multi-field form a guessing game.
        ValidationBehavior<SampleCommand, Unit> behavior = new([new SampleValidator()]);

        ValidationFailedException ex = await Should.ThrowAsync<ValidationFailedException>(
            () => behavior.Handle(
                new SampleCommand(string.Empty),
                _ => Task.FromResult(Unit.Value),
                CancellationToken.None));

        ex.Errors.ShouldContainKey(nameof(SampleCommand.Name));
        ex.Errors[nameof(SampleCommand.Name)].ShouldContain("A name is required.");
    }

    [Fact]
    public async Task A_request_with_no_validators_passes_straight_through()
    {
        ValidationBehavior<SampleCommand, Unit> behavior = new([]);

        bool handlerRan = false;

        await behavior.Handle(
            new SampleCommand(string.Empty),
            _ => { handlerRan = true; return Task.FromResult(Unit.Value); },
            CancellationToken.None);

        handlerRan.ShouldBeTrue();
    }
}

public sealed class TransactionBehaviorTests
{
    private sealed record WriteCommand : ICommand<Unit>, ITransactionalRequest;

    private sealed record ReadQuery : IQuery<Unit>;

    [Fact]
    public async Task A_transactional_request_gets_a_transaction()
    {
        FakeTransactionManager transactions = new();
        TransactionBehavior<WriteCommand, Unit> behavior =
            new(transactions, NullLogger<TransactionBehavior<WriteCommand, Unit>>.Instance);

        await behavior.Handle(
            new WriteCommand(),
            _ => Task.FromResult(Unit.Value),
            CancellationToken.None);

        transactions.ScopedTransactionCount.ShouldBe(1);
    }

    [Fact]
    public async Task A_query_does_not_open_a_transaction()
    {
        // Not a micro-optimisation: under SQLite, write transactions serialise, so a
        // transaction opened for a read steals a writer slot from the queue processor.
        FakeTransactionManager transactions = new();
        TransactionBehavior<ReadQuery, Unit> behavior =
            new(transactions, NullLogger<TransactionBehavior<ReadQuery, Unit>>.Instance);

        await behavior.Handle(
            new ReadQuery(),
            _ => Task.FromResult(Unit.Value),
            CancellationToken.None);

        transactions.ScopedTransactionCount.ShouldBe(0);
    }
}

public sealed class AuditBehaviorTests
{
    private sealed record AuditedCommand : ICommand<Unit>, IAuditableRequest
    {
        public AuditDescriptor DescribeForAudit() =>
            new("Test.Audited", "TestTarget", "target-id", "safe detail");
    }

    private sealed record UnauditedCommand : ICommand<Unit>;

    [Fact]
    public async Task A_success_is_recorded_immediately_so_it_commits_with_the_change()
    {
        FakeAuditTrail audit = new();
        AuditBehavior<AuditedCommand, Unit> behavior =
            new(audit, NullLogger<AuditBehavior<AuditedCommand, Unit>>.Instance);

        await behavior.Handle(
            new AuditedCommand(),
            _ => Task.FromResult(Unit.Value),
            CancellationToken.None);

        (AuditDescriptor Descriptor, AuditResult Result, string? Detail) recorded =
            audit.Recorded.ShouldHaveSingleItem();

        recorded.Result.ShouldBe(AuditResult.Success);
        recorded.Descriptor.Action.ShouldBe("Test.Audited");
        audit.Deferred.ShouldBeEmpty();
    }

    [Fact]
    public async Task A_failure_is_deferred_so_it_survives_the_rollback()
    {
        FakeAuditTrail audit = new();
        AuditBehavior<AuditedCommand, Unit> behavior =
            new(audit, NullLogger<AuditBehavior<AuditedCommand, Unit>>.Instance);

        await Should.ThrowAsync<InvalidOperationException>(
            () => behavior.Handle(
                new AuditedCommand(),
                _ => throw new InvalidOperationException("handler blew up"),
                CancellationToken.None));

        // Written immediately, it would be rolled back along with the failed transaction -
        // and the record of the failure would vanish with the failure itself.
        audit.Recorded.ShouldBeEmpty();
        audit.Deferred.ShouldHaveSingleItem().Result.ShouldBe(AuditResult.Failure);
    }

    [Fact]
    public async Task A_request_that_is_not_auditable_writes_nothing()
    {
        FakeAuditTrail audit = new();
        AuditBehavior<UnauditedCommand, Unit> behavior =
            new(audit, NullLogger<AuditBehavior<UnauditedCommand, Unit>>.Instance);

        await behavior.Handle(
            new UnauditedCommand(),
            _ => Task.FromResult(Unit.Value),
            CancellationToken.None);

        audit.Recorded.ShouldBeEmpty();
        audit.Deferred.ShouldBeEmpty();
    }

    [Fact]
    public async Task A_failure_detail_is_truncated_rather_than_stored_unbounded()
    {
        FakeAuditTrail audit = new();
        AuditBehavior<AuditedCommand, Unit> behavior =
            new(audit, NullLogger<AuditBehavior<AuditedCommand, Unit>>.Instance);

        string enormous = new('x', 10_000);

        await Should.ThrowAsync<InvalidOperationException>(
            () => behavior.Handle(
                new AuditedCommand(),
                _ => throw new InvalidOperationException(enormous),
                CancellationToken.None));

        // The audit table is not a log sink. A SQL error can carry a whole statement, and
        // an unbounded detail column would happily store it on every failure.
        audit.Deferred.ShouldHaveSingleItem().Detail!.Length.ShouldBeLessThanOrEqualTo(512);
    }
}
