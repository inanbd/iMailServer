using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Policies;

/// <summary>The outcome of expanding an address through the alias graph.</summary>
/// <param name="Recipients">The distinct addresses mail should actually be delivered to.</param>
/// <param name="WasTruncated">
/// True when a limit stopped the expansion, so the result is incomplete.
/// </param>
/// <param name="Diagnostic">Why it stopped, for the log and for the operator.</param>
public sealed record AliasExpansion(
    IReadOnlyList<EmailAddress> Recipients,
    bool WasTruncated = false,
    string? Diagnostic = null);

/// <summary>
/// Bounds on expanding an alias into a recipient list.
/// </summary>
/// <remarks>
/// <para>
/// <b>Both bounds exist because an alias graph is attacker-influenced in practice.</b> Not
/// usually by an outside attacker — by an operator who builds <c>all@</c> from <c>staff@</c>
/// from <c>everyone@</c> and creates a cycle without noticing, or who points a team alias at a
/// list that points back.
/// </para>
/// <list type="bullet">
///   <item><description><b>Depth</b> stops a cycle. Without it, expansion recurses until the
///   stack or the process gives out — on the SMTP path, for every message.</description></item>
///   <item><description><b>Breadth</b> stops amplification. One message to one address turning
///   into several hundred deliveries is a resource-exhaustion problem and, if any target is
///   external, an outbound reputation problem: a server that emits a burst of near-identical
///   messages looks exactly like a compromised one.</description></item>
/// </list>
/// <para>
/// Visited-set tracking catches most cycles before the depth limit does, and produces a better
/// message. The depth limit is the backstop for the case the visited set cannot see — a graph
/// that is deep without repeating.
/// </para>
/// </remarks>
public sealed class AliasExpansionPolicy
{
    /// <summary>
    /// How many alias hops one address may traverse.
    /// </summary>
    /// <remarks>
    /// Ten is generous for anything deliberate. Real structures are two or three deep —
    /// <c>all@</c> → <c>engineering@</c> → a person — and anything approaching ten is a
    /// mistake rather than a design.
    /// </remarks>
    public int MaxDepth { get; init; } = 10;

    /// <summary>
    /// How many recipients one expansion may produce.
    /// </summary>
    /// <remarks>
    /// The amplification bound. A hundred is well above a normal team alias and well below the
    /// point at which one inbound message becomes an outbound burst.
    /// </remarks>
    public int MaxRecipients { get; init; } = 100;

    /// <summary>
    /// Expands <paramref name="address"/> using <paramref name="resolveAlias"/>.
    /// </summary>
    /// <param name="address">The address mail was sent to.</param>
    /// <param name="resolveAlias">
    /// Returns the targets of an alias, or null when the address is not an alias — a mailbox,
    /// or external.
    /// </param>
    /// <remarks>
    /// <para>
    /// Breadth-first with a visited set. Breadth-first rather than depth-first so that the
    /// recipient limit truncates the <i>widest</i> part of the graph rather than one arbitrary
    /// branch of it, which makes a truncated result more useful and its diagnostic more
    /// accurate.
    /// </para>
    /// <para>
    /// A truncated expansion is reported, never silently trimmed. Delivering to some of a
    /// distribution list and telling nobody is worse than refusing: the sender believes it
    /// reached everyone.
    /// </para>
    /// </remarks>
    public AliasExpansion Expand(
        EmailAddress address,
        Func<EmailAddress, IReadOnlyList<EmailAddress>?> resolveAlias)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(resolveAlias);

        List<EmailAddress> recipients = [];
        HashSet<string> delivered = new(StringComparer.OrdinalIgnoreCase);
        HashSet<string> visitedAliases = new(StringComparer.OrdinalIgnoreCase);

        Queue<(EmailAddress Address, int Depth)> pending = new();
        pending.Enqueue((address, 0));

        while (pending.Count > 0)
        {
            (EmailAddress current, int depth) = pending.Dequeue();

            IReadOnlyList<EmailAddress>? targets = resolveAlias(current);

            if (targets is null)
            {
                // Not an alias: a mailbox or an external address, so it is a real recipient.
                if (delivered.Add(current.NormalizedValue))
                {
                    recipients.Add(current);

                    if (recipients.Count >= MaxRecipients)
                    {
                        return new AliasExpansion(
                            recipients,
                            true,
                            $"Expansion of '{address.Value}' reached the {MaxRecipients}-" +
                            "recipient limit and was stopped. Some recipients were not " +
                            "resolved. Check for an alias that fans out further than intended.");
                    }
                }

                continue;
            }

            if (depth >= MaxDepth)
            {
                return new AliasExpansion(
                    recipients,
                    true,
                    $"Expansion of '{address.Value}' reached the {MaxDepth}-hop limit at " +
                    $"'{current.Value}' and was stopped. This almost always means an alias " +
                    "cycle.");
            }

            if (!visitedAliases.Add(current.NormalizedValue))
            {
                // A cycle, caught earlier and more precisely than the depth limit would. Not
                // fatal: the rest of the graph still expands, and the addresses reachable by
                // another route are still delivered to.
                continue;
            }

            foreach (EmailAddress target in targets)
            {
                pending.Enqueue((target, depth + 1));
            }
        }

        return new AliasExpansion(recipients);
    }
}
