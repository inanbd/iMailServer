using MailServer.Domain.Exceptions;
using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// An address that forwards to one or more other addresses.
/// </summary>
/// <remarks>
/// <para>
/// An alias has no mailbox and stores nothing. Mail addressed to it is redirected to its
/// targets at delivery time, which is what makes <c>sales@</c> reach four people without four
/// copies of the message existing.
/// </para>
/// <para>
/// <b>Targets may themselves be aliases.</b> That is a genuinely useful arrangement —
/// <c>everyone@</c> pointing at <c>sales@</c> and <c>support@</c> — and it is also how an alias
/// loop is built, so expansion is bounded in both depth and breadth. See
/// <c>AliasExpansionPolicy</c>.
/// </para>
/// <para>
/// <b>Targets are not required to be local.</b> Forwarding to an external address is a normal
/// thing to want, and refusing it would push operators towards worse workarounds. It does have
/// a consequence they should understand: forwarded mail arrives at the destination from this
/// server, so SPF will see this server rather than the original sender. Milestone 9's Sender
/// Rewriting Scheme is what makes that survive.
/// </para>
/// </remarks>
public sealed class Alias : AggregateRoot<AliasId>
{
    private readonly List<EmailAddress> _targets;

    /// <summary>Rehydration constructor for the persistence layer.</summary>
    public Alias(
        AliasId id,
        DomainId domainId,
        EmailAddress address,
        IEnumerable<EmailAddress> targets,
        string? description,
        bool isEnabled,
        DateTimeOffset createdUtc,
        DateTimeOffset? modifiedUtc) : base(id)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(targets);

        DomainId = domainId;
        Address = address;
        _targets = [.. targets];
        Description = description;
        IsEnabled = isEnabled;
        CreatedUtc = createdUtc;
        ModifiedUtc = modifiedUtc;
    }

    public DomainId DomainId { get; }

    /// <summary>The address being aliased. Immutable, for the same reason a mailbox's is.</summary>
    public EmailAddress Address { get; }

    /// <summary>Where mail to <see cref="Address"/> goes.</summary>
    public IReadOnlyList<EmailAddress> Targets => _targets;

    /// <summary>Why this alias exists, for the operator who inherits it.</summary>
    /// <remarks>
    /// Worth having. An alias with no explanation is one nobody dares remove, and a domain
    /// accumulates them.
    /// </remarks>
    public string? Description { get; private set; }

    public bool IsEnabled { get; private set; }

    public DateTimeOffset CreatedUtc { get; }

    public DateTimeOffset? ModifiedUtc { get; private set; }

    /// <summary>True when this alias fans one message out to several recipients.</summary>
    public bool IsDistributionList => _targets.Count > 1;

    /// <summary>Creates an alias.</summary>
    /// <exception cref="DomainRuleViolationException">
    /// There are no targets, the alias points at itself, or a target is duplicated.
    /// </exception>
    public static Alias Create(
        DomainId domainId,
        EmailAddress address,
        MailDomain domain,
        IEnumerable<EmailAddress> targets,
        string? description,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(domain);
        ArgumentNullException.ThrowIfNull(targets);

        if (address.Domain != domain.Name)
        {
            throw new DomainRuleViolationException(
                "alias.address.wrong_domain",
                $"'{address.Value}' is not an address in '{domain.Name}'.");
        }

        List<EmailAddress> validated = ValidateTargets(address, targets);

        return new Alias(
            AliasId.New(),
            domainId,
            address,
            validated,
            string.IsNullOrWhiteSpace(description) ? null : description.Trim(),
            isEnabled: true,
            createdUtc: now,
            modifiedUtc: null);
    }

    /// <summary>Replaces the target list.</summary>
    public void SetTargets(IEnumerable<EmailAddress> targets, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(targets);

        _targets.Clear();
        _targets.AddRange(ValidateTargets(Address, targets));

        ModifiedUtc = now;
    }

    public void SetDescription(string? description, DateTimeOffset now)
    {
        Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim();
        ModifiedUtc = now;
    }

    public void SetEnabled(bool isEnabled, DateTimeOffset now)
    {
        IsEnabled = isEnabled;
        ModifiedUtc = now;
    }

    /// <summary>
    /// Checks a proposed target list.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Direct self-reference is the one loop that can be caught without loading anything else,
    /// so it is caught here. Longer cycles — A to B to A — need the whole alias graph and are
    /// the expansion resolver's job; the aggregate cannot see them.
    /// </para>
    /// <para>
    /// Duplicates are removed rather than rejected. Listing an address twice is a paste error,
    /// not an intent, and the alternative is delivering two copies to one person.
    /// </para>
    /// </remarks>
    private static List<EmailAddress> ValidateTargets(
        EmailAddress address,
        IEnumerable<EmailAddress> targets)
    {
        List<EmailAddress> distinct = [];
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

        foreach (EmailAddress target in targets)
        {
            if (string.Equals(
                    target.NormalizedValue,
                    address.NormalizedValue,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new DomainRuleViolationException(
                    "alias.target.self_reference",
                    $"'{address.Value}' cannot forward to itself. Mail to it would be " +
                    "redirected back to the same address indefinitely.");
            }

            if (seen.Add(target.NormalizedValue))
            {
                distinct.Add(target);
            }
        }

        if (distinct.Count == 0)
        {
            throw new DomainRuleViolationException(
                "alias.no_targets",
                $"'{address.Value}' must forward to at least one address. An alias with no " +
                "targets would accept mail and discard it silently.");
        }

        return distinct;
    }
}
