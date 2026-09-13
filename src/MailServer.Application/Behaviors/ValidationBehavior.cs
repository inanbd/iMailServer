using FluentValidation;
using FluentValidation.Results;
using MailServer.Application.Exceptions;
using MediatR;

namespace MailServer.Application.Behaviors;

/// <summary>
/// Pipeline stage 6 of 8. Runs every registered validator for the request and aggregates
/// the failures.
/// </summary>
/// <remarks>
/// <para>
/// <b>Placed before the transaction stage</b>, so a malformed request never opens a database
/// transaction. Under SQLite that matters concretely: write transactions serialise, and
/// opening one only to roll it back because a field was empty steals a writer slot from the
/// queue processor.
/// </para>
/// <para>
/// All validators run and all failures are collected. Returning only the first error makes
/// a multi-field form a guessing game for the administrator.
/// </para>
/// </remarks>
public sealed class ValidationBehavior<TRequest, TResponse>(
    IEnumerable<IValidator<TRequest>> validators)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : notnull
{
    public async Task<TResponse> Handle(
        TRequest request,
        RequestHandlerDelegate<TResponse> next,
        CancellationToken cancellationToken)
    {
        // Materialise once: the container may hand back a lazily-built enumerable.
        IValidator<TRequest>[] applicable = [.. validators];

        if (applicable.Length == 0)
        {
            return await next(cancellationToken).ConfigureAwait(false);
        }

        ValidationContext<TRequest> context = new(request);

        ValidationResult[] results = await Task.WhenAll(
            applicable.Select(v => v.ValidateAsync(context, cancellationToken))).ConfigureAwait(false);

        ValidationFailure[] failures = [.. results
            .Where(r => !r.IsValid)
            .SelectMany(r => r.Errors)
            .Where(f => f is not null)];

        if (failures.Length > 0)
        {
            Dictionary<string, string[]> errors = failures
                .GroupBy(f => f.PropertyName, StringComparer.Ordinal)
                .ToDictionary(
                    g => g.Key,
                    g => g.Select(f => f.ErrorMessage).Distinct(StringComparer.Ordinal).ToArray(),
                    StringComparer.Ordinal);

            throw new ValidationFailedException(errors);
        }

        return await next(cancellationToken).ConfigureAwait(false);
    }
}
