using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Repositories;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Mailboxes.Dtos;
using MailServer.Application.Mailboxes.Queries;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.Policies;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Mailboxes.Commands;

/// <summary>Creates an alias.</summary>
public sealed record CreateAliasCommand : ICommand<AliasDto>,
                                          ITransactionalRequest,
                                          IAuditableRequest,
                                          IAuthorizedRequest
{
    public required Guid DomainId { get; init; }

    /// <summary>The local-part of the alias, e.g. <c>sales</c>.</summary>
    public required string LocalPart { get; init; }

    /// <summary>Where mail to it goes. May be local or external.</summary>
    public required IReadOnlyList<string> Targets { get; init; }

    public string? Description { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageMailboxes;

    public AuditDescriptor DescribeForAudit() =>
        new("Alias.Create",
            nameof(Alias),
            LocalPart,
            $"{Targets.Count} target(s).");
}

internal sealed class CreateAliasCommandHandler(
    IAliasRepository aliases,
    IMailboxRepository mailboxes,
    IDomainRepository domains,
    IClock clock,
    ILogger<CreateAliasCommandHandler> logger)
    : IRequestHandler<CreateAliasCommand, AliasDto>
{
    public async Task<AliasDto> Handle(
        CreateAliasCommand request,
        CancellationToken cancellationToken)
    {
        DomainId domainId = new(request.DomainId);

        MailDomain domain =
            await domains.GetByIdAsync(domainId, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(MailDomain), request.DomainId.ToString());

        EmailAddress address = EmailAddress.Parse($"{request.LocalPart.Trim()}@{domain.Name.Value}");

        await CreateMailboxCommandHandler
            .EnsureAddressIsFreeAsync(mailboxes, aliases, address, cancellationToken)
            .ConfigureAwait(false);

        List<EmailAddress> targets = [.. request.Targets.Select(EmailAddress.Parse)];

        Alias alias = Alias.Create(
            domainId,
            address,
            domain,
            targets,
            request.Description,
            clock.UtcNow);

        // Checked against the alias graph as it WOULD be, not as it is. Adding the new alias to
        // the map before expanding is what makes a cycle detectable at creation rather than at
        // the first message.
        await RefuseIfItCreatesACycleAsync(aliases, alias, cancellationToken).ConfigureAwait(false);

        await aliases.AddAsync(alias, cancellationToken).ConfigureAwait(false);

        logger.LogInformation(
            "Created alias {Address} with {TargetCount} target(s).",
            address.NormalizedValue,
            targets.Count);

        HashSet<string> local = await GetAliasesQueryHandler
            .BuildLocalAddressSetAsync(mailboxes, aliases, domainId, cancellationToken)
            .ConfigureAwait(false);

        return MailboxMapper.ToDto(alias, local);
    }

    /// <summary>
    /// Refuses an alias that would make expansion loop or fan out beyond the limit.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The aggregate catches direct self-reference, which is all it can see. A cycle through
    /// two or more aliases needs the whole graph, and the graph is not the aggregate's to load.
    /// </para>
    /// <para>
    /// Caught at creation rather than left to the expansion limiter at delivery. The limiter
    /// terminates safely either way, but it does so by silently dropping recipients — and the
    /// operator who built the cycle is the one person who can fix it, at the moment they are
    /// looking at it.
    /// </para>
    /// </remarks>
    internal static async Task RefuseIfItCreatesACycleAsync(
        IAliasRepository aliases,
        Alias candidate,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<Alias> existing =
            await aliases.GetAllEnabledAsync(cancellationToken).ConfigureAwait(false);

        Dictionary<string, IReadOnlyList<EmailAddress>> graph =
            new(StringComparer.OrdinalIgnoreCase);

        foreach (Alias alias in existing)
        {
            // Skip the candidate's own previous version, so an edit is evaluated against what
            // it is becoming rather than against what it was.
            if (alias.Id != candidate.Id)
            {
                graph[alias.Address.NormalizedValue] = alias.Targets;
            }
        }

        graph[candidate.Address.NormalizedValue] = candidate.Targets;

        AliasExpansionPolicy policy = new();

        AliasExpansion expansion = policy.Expand(
            candidate.Address,
            address => graph.GetValueOrDefault(address.NormalizedValue));

        if (expansion.WasTruncated)
        {
            throw new DomainRuleViolationException(
                "alias.expansion.unbounded",
                $"'{candidate.Address.Value}' cannot be saved: {expansion.Diagnostic}");
        }

        if (expansion.Recipients.Count == 0)
        {
            throw new DomainRuleViolationException(
                "alias.expansion.no_recipients",
                $"'{candidate.Address.Value}' expands to no deliverable recipient. Every " +
                "target is itself an alias that leads back into the loop, so mail to this " +
                "address would be accepted and then delivered to nobody.");
        }
    }
}

// =========================================================================================

/// <summary>Changes an alias's targets, description or enabled state.</summary>
public sealed record UpdateAliasCommand : ICommand<Unit>,
                                          ITransactionalRequest,
                                          IAuditableRequest,
                                          IAuthorizedRequest
{
    public required Guid AliasId { get; init; }

    public IReadOnlyList<string>? Targets { get; init; }

    public string? Description { get; init; }

    public bool? IsEnabled { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageMailboxes;

    public AuditDescriptor DescribeForAudit() =>
        new("Alias.Update",
            nameof(Alias),
            AliasId.ToString(),
            Targets is null ? null : $"Targets set to {Targets.Count} address(es).");
}

internal sealed class UpdateAliasCommandHandler(
    IAliasRepository aliases,
    IClock clock)
    : IRequestHandler<UpdateAliasCommand, Unit>
{
    public async Task<Unit> Handle(
        UpdateAliasCommand request,
        CancellationToken cancellationToken)
    {
        AliasId id = new(request.AliasId);

        Alias alias =
            await aliases.GetAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(Alias), request.AliasId.ToString());

        DateTimeOffset now = clock.UtcNow;

        if (request.Targets is not null)
        {
            alias.SetTargets([.. request.Targets.Select(EmailAddress.Parse)], now);

            await CreateAliasCommandHandler
                .RefuseIfItCreatesACycleAsync(aliases, alias, cancellationToken)
                .ConfigureAwait(false);
        }

        if (request.Description is not null)
        {
            alias.SetDescription(request.Description, now);
        }

        if (request.IsEnabled is { } enabled)
        {
            alias.SetEnabled(enabled, now);
        }

        await aliases.UpdateAsync(alias, cancellationToken).ConfigureAwait(false);

        return Unit.Value;
    }
}

// =========================================================================================

/// <summary>Removes an alias.</summary>
public sealed record DeleteAliasCommand : ICommand<Unit>,
                                          ITransactionalRequest,
                                          IAuditableRequest,
                                          IAuthorizedRequest
{
    public required Guid AliasId { get; init; }

    public AdminPermission RequiredPermission => AdminPermission.ManageMailboxes;

    public AuditDescriptor DescribeForAudit() =>
        new("Alias.Delete", nameof(Alias), AliasId.ToString(), null);
}

internal sealed class DeleteAliasCommandHandler(
    IAliasRepository aliases,
    ILogger<DeleteAliasCommandHandler> logger)
    : IRequestHandler<DeleteAliasCommand, Unit>
{
    public async Task<Unit> Handle(
        DeleteAliasCommand request,
        CancellationToken cancellationToken)
    {
        AliasId id = new(request.AliasId);

        Alias alias =
            await aliases.GetAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new EntityNotFoundException(nameof(Alias), request.AliasId.ToString());

        await aliases.RemoveAsync(id, cancellationToken).ConfigureAwait(false);

        // Worth a log line: mail to this address now bounces, and the bounce reaches a sender
        // rather than anyone here. Deleting an alias is a silent change from this side.
        logger.LogInformation(
            "Deleted alias {Address}. Mail to it will now be rejected.",
            alias.Address.NormalizedValue);

        return Unit.Value;
    }
}
