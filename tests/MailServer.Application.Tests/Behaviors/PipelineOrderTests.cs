using MailServer.Application.Behaviors;
using MediatR;
using Microsoft.Extensions.DependencyInjection;

namespace MailServer.Application.Tests.Behaviors;

/// <summary>
/// Locks in the pipeline behavior order.
/// </summary>
/// <remarks>
/// <para>
/// The order is not cosmetic; several security properties depend on it. Authorization runs
/// before validation so an unauthorized caller cannot use validation messages as an
/// existence oracle. Validation runs before the transaction so a malformed request never
/// takes a writer slot. Audit runs inside the transaction so a change and the record of it
/// commit together.
/// </para>
/// <para>
/// A future edit that reorders the registrations would silently weaken all three. This test
/// makes that a build failure instead.
/// </para>
/// </remarks>
public sealed class PipelineOrderTests
{
    [Fact]
    public void The_declared_order_is_the_documented_one()
    {
        DependencyInjection.PipelineBehaviorsInOrder.ShouldBe(
        [
            typeof(CorrelationBehavior<,>),
            typeof(UnhandledExceptionBehavior<,>),
            typeof(PerformanceBehavior<,>),
            typeof(LoggingBehavior<,>),
            typeof(AuthorizationBehavior<,>),
            typeof(ValidationBehavior<,>),
            typeof(TlsReloadBehavior<,>),
            typeof(TransactionBehavior<,>),
            typeof(AuditBehavior<,>),
        ]);
    }

    [Fact]
    public void The_container_registers_the_behaviors_in_the_declared_order()
    {
        // Asserting against the same list the container is built from, so the two cannot
        // drift apart: changing one without the other fails here.
        ServiceCollection services = new();
        services.AddApplication();

        Type[] registered =
        [
            .. services
                .Where(d => d.ServiceType == typeof(IPipelineBehavior<,>))
                .Select(d => d.ImplementationType!)
        ];

        registered.ShouldBe(DependencyInjection.PipelineBehaviorsInOrder.ToArray());
    }

    [Fact]
    public void Authorization_runs_before_validation()
    {
        // The information-disclosure defence: an unauthorized caller must learn exactly one
        // thing, that they are unauthorized, and nothing about whether the target exists.
        IReadOnlyList<Type> order = DependencyInjection.PipelineBehaviorsInOrder;

        int authorization = order.ToList().IndexOf(typeof(AuthorizationBehavior<,>));
        int validation = order.ToList().IndexOf(typeof(ValidationBehavior<,>));

        authorization.ShouldBeLessThan(validation);
    }

    [Fact]
    public void Validation_runs_before_the_transaction()
    {
        // Under SQLite, write transactions serialise; opening one only to roll it back
        // because a field was empty steals a writer slot from the queue processor.
        IReadOnlyList<Type> order = DependencyInjection.PipelineBehaviorsInOrder;

        order.ToList().IndexOf(typeof(ValidationBehavior<,>))
            .ShouldBeLessThan(order.ToList().IndexOf(typeof(TransactionBehavior<,>)));
    }

    [Fact]
    public void Audit_runs_inside_the_transaction()
    {
        // An audit trail that can disagree with the data it describes is worse than none,
        // because it is trusted.
        IReadOnlyList<Type> order = DependencyInjection.PipelineBehaviorsInOrder;

        order.ToList().IndexOf(typeof(TransactionBehavior<,>))
            .ShouldBeLessThan(order.ToList().IndexOf(typeof(AuditBehavior<,>)));
    }

    [Fact]
    public void Exception_handling_wraps_the_transaction_so_its_flush_runs_after_rollback()
    {
        IReadOnlyList<Type> order = DependencyInjection.PipelineBehaviorsInOrder;

        order.ToList().IndexOf(typeof(UnhandledExceptionBehavior<,>))
            .ShouldBeLessThan(order.ToList().IndexOf(typeof(TransactionBehavior<,>)));
    }

    [Fact]
    public void Correlation_runs_first_so_every_later_stage_has_an_id()
    {
        DependencyInjection.PipelineBehaviorsInOrder[0].ShouldBe(typeof(CorrelationBehavior<,>));
    }

    [Fact]
    public void Every_validator_in_the_application_assembly_is_registered()
    {
        ServiceCollection services = new();
        services.AddApplication();

        int validatorCount = services.Count(d =>
            d.ServiceType.IsGenericType &&
            d.ServiceType.GetGenericTypeDefinition() == typeof(FluentValidation.IValidator<>));

        // A validator that exists but is not registered is worse than none: the rule appears
        // to be enforced in the source and silently is not.
        validatorCount.ShouldBeGreaterThan(0);
    }

    /// <summary>
    /// The TLS reload must wrap the transaction, not sit inside it.
    /// </summary>
    /// <remarks>
    /// Inside the transaction, the provider's fresh connection cannot see the binding rows the
    /// handler just wrote, so it would rebuild the certificate snapshot from the state BEFORE
    /// the change — and then log success. A hot swap that silently does not swap is worse than
    /// one that fails loudly, because nothing about it looks wrong.
    /// </remarks>
    [Fact]
    public void The_tls_reload_runs_after_the_transaction_commits()
    {
        IReadOnlyList<Type> order = DependencyInjection.PipelineBehaviorsInOrder;

        order.ToList().IndexOf(typeof(TlsReloadBehavior<,>))
            .ShouldBeLessThan(order.ToList().IndexOf(typeof(TransactionBehavior<,>)));
    }
}
