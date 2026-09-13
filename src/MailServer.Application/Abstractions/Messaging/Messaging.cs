using MailServer.Domain.Enums;
using MailServer.Domain.ValueObjects;
using MediatR;

namespace MailServer.Application.Abstractions.Messaging;

/// <summary>
/// A use case that changes state.
/// </summary>
/// <remarks>
/// Commands and queries are distinguished by marker interfaces rather than by naming
/// convention so that the pipeline can make decisions (open a transaction, write an audit
/// record) from the type system instead of from a string suffix.
/// </remarks>
public interface ICommand<out TResponse> : IRequest<TResponse>;

/// <summary>A command with no meaningful return value.</summary>
public interface ICommand : IRequest<Unit>;

/// <summary>A use case that reads state and changes nothing.</summary>
public interface IQuery<out TResponse> : IRequest<TResponse>;

/// <summary>
/// Opts a request into an ambient database transaction spanning its whole handler.
/// </summary>
/// <remarks>
/// Applied to commands. Deliberately NOT applied to queries: opening a transaction for a
/// read costs a writer slot, which under SQLite's single-writer model is a direct
/// throughput loss for no benefit.
/// </remarks>
public interface ITransactionalRequest;

/// <summary>
/// Opts a request into audit-trail persistence.
/// </summary>
/// <remarks>
/// <para>
/// The request describes itself rather than being serialised by the pipeline. That is the
/// whole point: a generic reflect-and-store audit behavior would faithfully write a new
/// mailbox password, an imported PFX passphrase or a smarthost credential into the audit
/// table the moment somebody added such a field to a command.
/// </para>
/// <para>
/// Because the descriptor is written by hand, a newly added secret-bearing field is absent
/// from the audit trail until a developer deliberately puts it there.
/// </para>
/// </remarks>
public interface IAuditableRequest
{
    /// <summary>Returns only the values that are safe to record permanently.</summary>
    AuditDescriptor DescribeForAudit();
}

/// <summary>
/// Marks a request as reachable <b>without</b> an authenticated session.
/// </summary>
/// <remarks>
/// <para>
/// Applied to exactly four requests: asking whether setup is required, completing setup,
/// signing in, and resetting the password with a recovery key. Nothing else may carry it.
/// </para>
/// <para>
/// <c>IpcCommandRegistry</c> cross-checks this marker against each command descriptor's
/// <c>RequiresSession</c> flag and refuses to build if the two disagree. A command whose
/// descriptor says "no session needed" but whose type is not marked anonymous — or the
/// reverse — is a bug that would either expose an administrative operation or make an
/// unreachable sign-in screen, so it fails at startup rather than in production.
/// </para>
/// </remarks>
public interface IAnonymousRequest;

/// <summary>
/// Marks a request as permitted while the signed-in administrator still owes a password
/// change.
/// </summary>
/// <remarks>
/// After a recovery-key reset the administrator holds a valid session but has not yet chosen a
/// password. That session must be able to change the password and to sign out, and nothing
/// else — otherwise a recovery key would be a permanent bypass of the password entirely.
/// </remarks>
public interface IAllowedWhenPasswordChangeRequired;

/// <summary>
/// Opts a request into permission enforcement.
/// </summary>
/// <remarks>
/// Every request reachable over IPC must implement this. <c>IpcCommandRegistry</c> refuses
/// at startup to register a command that does not, so "forgot to add authorization" fails
/// the build's startup test rather than shipping as an unauthenticated administrative
/// endpoint.
/// </remarks>
public interface IAuthorizedRequest
{
    /// <summary>The permission the calling session must hold.</summary>
    AdminPermission RequiredPermission { get; }
}
