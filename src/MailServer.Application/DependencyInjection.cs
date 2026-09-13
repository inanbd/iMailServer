using System.Reflection;
using FluentValidation;
using MailServer.Application.Behaviors;
using Microsoft.Extensions.DependencyInjection;

namespace MailServer.Application;

/// <summary>
/// Registers the Application layer: MediatR, the pipeline, and every validator.
/// </summary>
public static class DependencyInjection
{
    /// <summary>The assembly containing the Application layer's handlers and validators.</summary>
    public static Assembly ApplicationAssembly => typeof(DependencyInjection).Assembly;

    /// <summary>
    /// Adds MediatR, the eight pipeline behaviors and all FluentValidation validators.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Behavior order is registration order, and it is load-bearing.</b> MediatR executes
    /// behaviors in the order they are added, outermost first. The reasoning for each
    /// position is on the behavior class itself; the summary is:
    /// </para>
    /// <list type="number">
    ///   <item><description><b>Correlation</b> - first, so everything below it, including
    ///   the exception logger, has an id to attach.</description></item>
    ///   <item><description><b>UnhandledException</b> - outside validation, authorization
    ///   and the transaction, so it catches failures thrown by those stages too, and so its
    ///   finally block runs after rollback.</description></item>
    ///   <item><description><b>Performance</b> - measures everything below, including
    ///   transaction setup, because that is part of what makes a request slow.</description></item>
    ///   <item><description><b>Logging</b> - records the attempt before authorization can
    ///   reject it, so denied attempts appear in the log.</description></item>
    ///   <item><description><b>Authorization</b> - before validation, so an unauthorized
    ///   caller cannot use validation messages as an existence oracle.</description></item>
    ///   <item><description><b>Validation</b> - before the transaction, so a malformed
    ///   request never takes a writer slot.</description></item>
    ///   <item><description><b>Transaction</b> - one transaction per use case.</description></item>
    ///   <item><description><b>Audit</b> - innermost, inside the transaction, so the audit
    ///   record and the change it describes commit together.</description></item>
    /// </list>
    /// <para>
    /// <c>ApplicationPipelineTests</c> asserts this order, so a future edit that reorders
    /// these lines fails the build rather than silently weakening the security properties
    /// above.
    /// </para>
    /// </remarks>
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddMediatR(configuration =>
        {
            configuration.RegisterServicesFromAssembly(ApplicationAssembly);

            configuration.AddOpenBehavior(typeof(CorrelationBehavior<,>));
            configuration.AddOpenBehavior(typeof(UnhandledExceptionBehavior<,>));
            configuration.AddOpenBehavior(typeof(PerformanceBehavior<,>));
            configuration.AddOpenBehavior(typeof(LoggingBehavior<,>));
            configuration.AddOpenBehavior(typeof(AuthorizationBehavior<,>));
            configuration.AddOpenBehavior(typeof(ValidationBehavior<,>));
            configuration.AddOpenBehavior(typeof(TransactionBehavior<,>));
            configuration.AddOpenBehavior(typeof(AuditBehavior<,>));
        });

        // Validators are transient by default, which is what we want: they are cheap to
        // build and must not capture per-request state.
        services.AddValidatorsFromAssembly(ApplicationAssembly, includeInternalTypes: true);

        return services;
    }

    /// <summary>
    /// The pipeline behaviors in execution order. Exposed so that the pipeline-order test
    /// checks the same list the container is built from, rather than a copy that could
    /// drift.
    /// </summary>
    public static IReadOnlyList<Type> PipelineBehaviorsInOrder { get; } =
    [
        typeof(CorrelationBehavior<,>),
        typeof(UnhandledExceptionBehavior<,>),
        typeof(PerformanceBehavior<,>),
        typeof(LoggingBehavior<,>),
        typeof(AuthorizationBehavior<,>),
        typeof(ValidationBehavior<,>),
        typeof(TransactionBehavior<,>),
        typeof(AuditBehavior<,>),
    ];
}
