using MailServer.Domain.Enums;

namespace MailServer.Application.Abstractions.Security;

/// <summary>
/// Populates the scoped <see cref="IAdminContext"/> once a caller has been authenticated.
/// </summary>
/// <remarks>
/// <para>
/// Separated from <see cref="IAdminContext"/> on purpose. Handlers depend on
/// <c>IAdminContext</c> and can only <i>read</i> the identity; only the authentication
/// boundary resolves this interface and can <i>set</i> it. A single read-write interface
/// would let any handler quietly promote its own permissions.
/// </para>
/// <para>
/// This also keeps the IPC layer free of any Infrastructure reference. That matters beyond
/// tidiness: <c>MailServer.Admin</c> references <c>MailServer.Ipc</c>, so anything the IPC
/// layer depends on lands in the WPF application's dependency closure. Depending on
/// Infrastructure here would put Dapper and the database drivers in the admin application
/// and destroy the compile-time guarantee that the UI cannot touch the database.
/// </para>
/// </remarks>
public interface IAdminContextInitializer
{
    /// <summary>Assigns the authenticated identity for this scope.</summary>
    void Assign(
        string administrator,
        string? sessionIdentifier,
        AdminPermission permissions,
        bool isSystem = false,
        bool mustChangePassword = false);
}
