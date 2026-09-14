using System.Diagnostics.CodeAnalysis;
using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Common;
using MailServer.Application.Domains.Commands;
using MailServer.Application.Domains.Dtos;
using MailServer.Application.Acme.Commands;
using MailServer.Application.Acme.Dtos;
using MailServer.Application.Acme.Queries;
using MailServer.Application.Certificates.Commands;
using MailServer.Application.Certificates.Dtos;
using MailServer.Application.Certificates.Queries;
using MailServer.Application.Domains.Queries;
using MailServer.Application.Monitoring.Dtos;
using MailServer.Application.Monitoring.Queries;
using MailServer.Application.Security.Commands;
using MailServer.Application.Security.Dtos;
using MailServer.Application.Security.Queries;
using MediatR;

namespace MailServer.Ipc.Protocol;

/// <summary>One command the service is willing to accept over IPC.</summary>
/// <param name="Name">Wire name, e.g. <c>Domains.Create</c>.</param>
/// <param name="RequestType">The MediatR request this name maps to.</param>
/// <param name="ResponseType">The response type, for payload serialisation.</param>
/// <param name="RequiresSession">
/// False for the four commands reachable before sign-in. Cross-checked against the request
/// type's <see cref="IAnonymousRequest"/> marker at construction, so the flag and the type can
/// never disagree.
/// </param>
public sealed record IpcCommandDescriptor(
    string Name,
    Type RequestType,
    Type ResponseType,
    bool RequiresSession = true);

/// <summary>
/// The explicit allow-list of IPC-reachable operations.
/// </summary>
/// <remarks>
/// <para>
/// <b>This class is the IPC layer's primary security control.</b> The obvious implementation -
/// accept an assembly-qualified type name and call <c>Type.GetType</c> - would hand anyone who
/// can reach the pipe the ability to instantiate arbitrary types inside the service process.
/// That is a remote code execution primitive, traded away for the convenience of not writing a
/// dictionary.
/// </para>
/// <para>
/// Three invariants are checked at construction, so a mistake fails the service's first second
/// of life rather than shipping:
/// </para>
/// <list type="number">
///   <item><description>Every registered request declares a required permission.</description></item>
///   <item><description><c>RequiresSession</c> agrees with the <see cref="IAnonymousRequest"/>
///   marker in both directions. A command whose descriptor says "no session needed" but whose
///   type is not marked anonymous would be an unauthenticated administrative endpoint; the
///   reverse would be an unreachable sign-in screen.</description></item>
///   <item><description>No duplicate names, which would make dispatch depend on registration
///   order.</description></item>
/// </list>
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
            VerifyAnonymousMarkerAgrees(descriptor);

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
    /// Ordinal, case-sensitive. Case-insensitive matching would let one operation arrive under
    /// many spellings, which makes audit-log analysis and per-command rate limiting fuzzy.
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
    /// Ensures the descriptor's session requirement matches the request type's marker.
    /// </summary>
    /// <remarks>
    /// Checked in <b>both</b> directions on purpose. A descriptor marked
    /// <c>RequiresSession: false</c> against a type that is not
    /// <see cref="IAnonymousRequest"/> would expose an administrative operation to
    /// unauthenticated callers — the worst possible failure. The reverse is merely broken, but
    /// broken in a way that would only be discovered when somebody could not sign in.
    /// </remarks>
    private static void VerifyAnonymousMarkerAgrees(IpcCommandDescriptor descriptor)
    {
        bool isMarkedAnonymous = typeof(IAnonymousRequest).IsAssignableFrom(descriptor.RequestType);

        if (!descriptor.RequiresSession && !isMarkedAnonymous)
        {
            throw new InvalidOperationException(
                $"IPC command '{descriptor.Name}' is registered as not requiring a session, but " +
                $"{descriptor.RequestType.Name} does not implement {nameof(IAnonymousRequest)}. " +
                "This would expose an administrative operation to unauthenticated callers.");
        }

        if (descriptor.RequiresSession && isMarkedAnonymous)
        {
            throw new InvalidOperationException(
                $"IPC command '{descriptor.Name}' maps to {descriptor.RequestType.Name}, which " +
                $"implements {nameof(IAnonymousRequest)}, but the descriptor requires a session. " +
                "An anonymous request that cannot be reached without a session is unusable - " +
                "nobody could sign in.");
        }
    }

    /// <summary>
    /// The default command table.
    /// </summary>
    /// <remarks>
    /// A reviewer can see the entire externally-reachable surface of the service by reading
    /// this one method — which is exactly the property a security review needs. The four
    /// anonymous entries are grouped together and individually justified.
    /// </remarks>
    private static IEnumerable<IpcCommandDescriptor> BuildDefaultDescriptors() =>
    [
        // ---- Reachable WITHOUT a session -------------------------------------------------
        // These four, and only these four. Each is safe for a specific reason:
        //   SetupStatus     reveals only whether setup is needed and whether authentication is
        //                   currently locked out - both required to draw the right screen.
        //   CompleteSetup   refuses outright once an account exists, so it cannot be replayed
        //                   to seize a configured server.
        //   Authenticate    is the sign-in itself.
        //   ResetPassword…  requires the recovery key, which is 125 bits of entropy.
        new("Security.SetupStatus", typeof(GetSetupStatusQuery), typeof(SetupStatusDto), RequiresSession: false),
        new("Security.CompleteSetup", typeof(CompleteSetupCommand), typeof(SetupResultDto), RequiresSession: false),
        new("Security.Authenticate", typeof(AuthenticateCommand), typeof(AuthenticationResultDto), RequiresSession: false),
        new("Security.ResetPasswordWithRecoveryKey", typeof(ResetPasswordWithRecoveryKeyCommand), typeof(RecoveryKeyDto), RequiresSession: false),

        // ---- Security, authenticated ------------------------------------------------------
        new("Security.SignOut", typeof(SignOutCommand), typeof(Unit)),
        new("Security.ChangeMasterPassword", typeof(ChangeMasterPasswordCommand), typeof(Unit)),
        new("Security.Status", typeof(GetSecurityStatusQuery), typeof(SecurityStatusDto)),
        new("Security.Sessions", typeof(GetActiveSessionsQuery), typeof(IReadOnlyList<AdminSessionDto>)),
        new("Security.RevokeSession", typeof(RevokeSessionCommand), typeof(Unit)),
        new("Security.AuditLog", typeof(GetAuditLogQuery), typeof(PagedResult<AuditRecordDto>)),
        new("Security.Events", typeof(GetSecurityEventsQuery), typeof(PagedResult<SecurityEventDto>)),

        // ---- Domains ----------------------------------------------------------------------
        new("Domains.List", typeof(GetDomainsQuery), typeof(PagedResult<DomainSummaryDto>)),
        new("Domains.Get", typeof(GetDomainDetailsQuery), typeof(DomainDetailDto)),
        new("Domains.Create", typeof(CreateDomainCommand), typeof(DomainSummaryDto)),
        new("Domains.Update", typeof(UpdateDomainCommand), typeof(Unit)),
        new("Domains.SetStatus", typeof(SetDomainStatusCommand), typeof(Unit)),
        new("Domains.Delete", typeof(DeleteDomainCommand), typeof(Unit)),

        // ---- Certificates -------------------------------------------------------------------
        new("Certificates.List", typeof(GetCertificatesQuery), typeof(IReadOnlyList<CertificateDto>)),
        new("Certificates.Get", typeof(GetCertificateQuery), typeof(CertificateDto)),
        new("Certificates.Health", typeof(GetCertificateHealthQuery), typeof(CertificateHealthDto)),
        new("Certificates.AvailableInStore", typeof(GetAvailableStoreCertificatesQuery), typeof(IReadOnlyList<AvailableStoreCertificateDto>)),
        new("Certificates.GenerateSelfSigned", typeof(GenerateSelfSignedCertificateCommand), typeof(CertificateDto)),
        new("Certificates.Import", typeof(ImportCertificateCommand), typeof(CertificateDto)),
        new("Certificates.AdoptFromStore", typeof(AdoptStoreCertificateCommand), typeof(CertificateDto)),
        new("Certificates.Bind", typeof(BindCertificateCommand), typeof(Unit)),
        new("Certificates.Unbind", typeof(UnbindCertificateCommand), typeof(Unit)),
        new("Certificates.SetDefaultBinding", typeof(SetDefaultBindingCommand), typeof(Unit)),
        new("Certificates.Delete", typeof(DeleteCertificateCommand), typeof(Unit)),

        // ---- ACME / Let's Encrypt -------------------------------------------------------------
        new("Acme.Status", typeof(GetAcmeStatusQuery), typeof(AcmeStatusDto)),
        new("Acme.Accounts", typeof(GetAcmeAccountsQuery), typeof(IReadOnlyList<AcmeAccountDto>)),
        new("Acme.Orders", typeof(GetAcmeOrdersQuery), typeof(IReadOnlyList<AcmeOrderDto>)),
        new("Acme.CheckReadiness", typeof(CheckIssuanceReadinessCommand), typeof(IReadOnlyList<PreflightFindingDto>)),
        new("Acme.RequestCertificate", typeof(RequestCertificateCommand), typeof(IssuanceResultDto)),

        // ---- Monitoring ---------------------------------------------------------------------
        new("Monitoring.Dashboard", typeof(GetDashboardQuery), typeof(DashboardDto)),
    ];
}
