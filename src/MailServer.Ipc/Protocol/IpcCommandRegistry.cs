using System.Diagnostics.CodeAnalysis;
using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Common;
using MailServer.Application.Domains.Commands;
using MailServer.Application.Domains.Dtos;
using MailServer.Application.Domains.Queries;
using MailServer.Application.Monitoring.Dtos;
using MailServer.Application.Monitoring.Queries;
using MediatR;

namespace MailServer.Ipc.Protocol;

/// <summary>One command the service is willing to accept over IPC.</summary>
/// <param name="Name">Wire name, e.g. <c>Domains.Create</c>.</param>
/// <param name="RequestType">The MediatR request this name maps to.</param>
/// <param name="ResponseType">The response type, for payload serialisation.</param>
public sealed record IpcCommandDescriptor(string Name, Type RequestType, Type ResponseType);

/// <summary>
/// The explicit allow-list of IPC-reachable operations.
/// </summary>
/// <remarks>
/// <para>
/// <b>This class is the IPC layer's primary security control.</b> The obvious
/// implementation - accept an assembly-qualified type name and call <c>Type.GetType</c> -
/// would hand anyone who can reach the pipe the ability to instantiate arbitrary types
/// inside the service process. That is a remote code execution primitive, traded away for
/// the convenience of not writing a dictionary.
/// </para>
/// <para>
/// Instead, wire names map to types through this hand-written table. A request type that is
/// not listed here is unreachable from outside the process, whatever the caller sends.
/// </para>
/// <para>
/// <b>Every registered request must implement <see cref="IAuthorizedRequest"/>.</b> The
/// constructor verifies this and throws at startup otherwise, so "forgot to add
/// authorization" fails the service's first second of life rather than shipping as an
/// unauthenticated administrative endpoint.
/// </para>
/// </remarks>
public sealed class IpcCommandRegistry
{
    private readonly Dictionary<string, IpcCommandDescriptor> _byName;

    public IpcCommandRegistry() : this(BuildDefaultDescriptors())
    {
    }

    internal IpcCommandRegistry(IEnumerable<IpcCommandDescriptor> descriptors)
    {
        ArgumentNullException.ThrowIfNull(descriptors);

        _byName = new Dictionary<string, IpcCommandDescriptor>(StringComparer.Ordinal);

        foreach (IpcCommandDescriptor descriptor in descriptors)
        {
            VerifyAuthorizationIsDeclared(descriptor);

            if (!_byName.TryAdd(descriptor.Name, descriptor))
            {
                throw new InvalidOperationException(
                    $"IPC command '{descriptor.Name}' is registered more than once. Duplicate " +
                    "names would make dispatch depend on registration order.");
            }
        }
    }

    /// <summary>Every registered command, for diagnostics and for the registry test.</summary>
    public IReadOnlyCollection<IpcCommandDescriptor> Commands => _byName.Values;

    /// <summary>
    /// Resolves a wire name. Returns false for anything not explicitly registered.
    /// </summary>
    /// <remarks>
    /// Ordinal, case-sensitive comparison. Case-insensitive matching would mean the server
    /// accepts <c>domains.create</c>, <c>DOMAINS.CREATE</c> and every variation in between,
    /// which makes audit-log analysis and rate-limiting by command name unnecessarily fuzzy.
    /// </remarks>
    public bool TryResolve(string? name, [NotNullWhen(true)] out IpcCommandDescriptor? descriptor)
    {
        if (string.IsNullOrEmpty(name))
        {
            descriptor = null;
            return false;
        }

        return _byName.TryGetValue(name, out descriptor);
    }

    /// <summary>
    /// Enforces that every IPC-reachable request declares a required permission.
    /// </summary>
    /// <remarks>
    /// Uses the parameterless constructor to read the property. Every registered request is
    /// a record with defaulted members for exactly this reason; a request that cannot be
    /// constructed here fails the build's startup test, which is the correct outcome for
    /// something that must be checkable before it is ever dispatched.
    /// </remarks>
    private static void VerifyAuthorizationIsDeclared(IpcCommandDescriptor descriptor)
    {
        if (!typeof(IAuthorizedRequest).IsAssignableFrom(descriptor.RequestType))
        {
            throw new InvalidOperationException(
                $"IPC command '{descriptor.Name}' maps to {descriptor.RequestType.Name}, which " +
                $"does not implement {nameof(IAuthorizedRequest)}. Every operation reachable " +
                "over IPC must declare the permission it requires, otherwise the authorization " +
                "pipeline behavior has nothing to enforce and the command is effectively public.");
        }
    }

    /// <summary>
    /// The default command table.
    /// </summary>
    /// <remarks>
    /// Grows one deliberate line at a time as milestones land. A reviewer can see the entire
    /// externally-reachable surface of the service by reading this one method, which is
    /// exactly the property a security review needs.
    /// </remarks>
    private static IEnumerable<IpcCommandDescriptor> BuildDefaultDescriptors() =>
    [
        // ---- Domains -------------------------------------------------------------------
        new("Domains.List", typeof(GetDomainsQuery), typeof(PagedResult<DomainSummaryDto>)),
        new("Domains.Get", typeof(GetDomainDetailsQuery), typeof(DomainDetailDto)),
        new("Domains.Create", typeof(CreateDomainCommand), typeof(DomainSummaryDto)),
        new("Domains.Update", typeof(UpdateDomainCommand), typeof(Unit)),
        new("Domains.SetStatus", typeof(SetDomainStatusCommand), typeof(Unit)),
        new("Domains.Delete", typeof(DeleteDomainCommand), typeof(Unit)),

        // ---- Monitoring ----------------------------------------------------------------
        new("Monitoring.Dashboard", typeof(GetDashboardQuery), typeof(DashboardDto)),
    ];
}
