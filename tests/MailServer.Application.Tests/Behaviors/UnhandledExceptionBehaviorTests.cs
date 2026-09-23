using MailServer.Application.Abstractions.Security;
using MailServer.Application.Behaviors;
using MailServer.Application.Exceptions;
using MailServer.Application.Tests.Fakes;
using MailServer.Domain.Enums;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Tests.Behaviors;

/// <summary>
/// What reaches the error log.
/// </summary>
/// <remarks>
/// Every mistyped master password used to be logged as an error with the server's stack trace
/// attached. An error log that fills with the product working as designed is one an operator
/// learns to skim, and the real failure is then the line they skim past.
/// </remarks>
public sealed class UnhandledExceptionBehaviorTests
{
    private sealed record Probe : IRequest<Unit>;

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<(LogLevel Level, string Message, Exception? Exception)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception), exception));
    }

    private sealed class SilentSecurityEvents : ISecurityEventRecorder
    {
        public bool HasPendingEvents => false;

        public Task RecordAsync(
            SecurityEventType eventType,
            string? subject,
            string? origin,
            string description,
            CancellationToken cancellationToken) => Task.CompletedTask;

        public Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private static async Task<CapturingLogger<UnhandledExceptionBehavior<Probe, Unit>>> ThrowThroughAsync(Exception thrown)
    {
        CapturingLogger<UnhandledExceptionBehavior<Probe, Unit>> logger = new();

        UnhandledExceptionBehavior<Probe, Unit> behavior = new(new FakeAuditTrail(), new SilentSecurityEvents(), logger);

        Exception caught = await Should.ThrowAsync<Exception>(
            () => behavior.Handle(new Probe(), _ => throw thrown, CancellationToken.None));

        // Logged and rethrown unchanged: the caller still gets the refusal it was owed.
        caught.ShouldBeSameAs(thrown);

        return logger;
    }

    public static TheoryData<Exception> Refusals() =>
    [
        new AuthenticationFailedException("The master password is not correct."),
        new AccountLockedOutException(TimeSpan.FromMinutes(3)),
        new PasswordChangeRequiredException(),
        new MaintenanceModeException(MaintenanceMode.ReadOnly),
    ];

    [Theory]
    [MemberData(nameof(Refusals))]
    public async Task A_refusal_is_a_warning_without_a_stack_trace(Exception refusal)
    {
        CapturingLogger<UnhandledExceptionBehavior<Probe, Unit>> logger = await ThrowThroughAsync(refusal);

        (LogLevel level, string message, Exception? exception) = logger.Entries.ShouldHaveSingleItem();

        level.ShouldBe(LogLevel.Warning);
        exception.ShouldBeNull();
        message.ShouldContain(((ApplicationLayerException)refusal).Code);
    }

    [Fact]
    public async Task A_refusal_never_logs_what_the_caller_typed()
    {
        // The message is the server's own sentence, but the log line carries only the code: a
        // future refusal whose message echoed input would otherwise put it in the log.
        CapturingLogger<UnhandledExceptionBehavior<Probe, Unit>> logger =
            await ThrowThroughAsync(new AuthenticationFailedException("hunter2 is not the password"));

        (_, string message, Exception? exception) = logger.Entries.ShouldHaveSingleItem();

        // Both: a sink writes the attached exception's message beside the log line.
        message.ShouldNotContain("hunter2");
        exception.ShouldBeNull();
    }

    [Fact]
    public async Task A_failure_that_is_not_a_refusal_is_still_an_error_with_its_stack_trace()
    {
        Exception failure = new MigrationFailedException(15, "Quarantine", new InvalidOperationException("disk full"));

        CapturingLogger<UnhandledExceptionBehavior<Probe, Unit>> logger = await ThrowThroughAsync(failure);

        (LogLevel level, _, Exception? exception) = logger.Entries.ShouldHaveSingleItem();

        level.ShouldBe(LogLevel.Error);
        exception.ShouldBeSameAs(failure);
    }

    [Fact]
    public async Task An_unexpected_exception_is_still_an_error()
    {
        CapturingLogger<UnhandledExceptionBehavior<Probe, Unit>> logger =
            await ThrowThroughAsync(new NullReferenceException());

        logger.Entries.ShouldHaveSingleItem().Level.ShouldBe(LogLevel.Error);
    }

    [Fact]
    public void Only_the_named_refusals_are_refusals()
    {
        // The default is an error. A new application exception must opt in to being quiet,
        // and this names every one that has, so the list is reviewed rather than grown.
        string[] refusals =
        [
            .. typeof(ApplicationLayerException).Assembly
                .GetTypes()
                .Where(t => t.IsSubclassOf(typeof(ApplicationLayerException)) && !t.IsAbstract)
                .Where(t => t.GetProperty(nameof(ApplicationLayerException.IsRefusal))!.DeclaringType == t)
                .Select(t => t.Name)
                .Order(),
        ];

        refusals.ShouldBe(
        [
            nameof(AccountLockedOutException),
            nameof(AuthenticationFailedException),
            nameof(MaintenanceModeException),
            nameof(PasswordChangeRequiredException),
        ]);
    }
}
