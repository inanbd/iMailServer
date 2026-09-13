using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;

namespace MailServer.Ipc.Server;

/// <summary>
/// Creates the named-pipe server stream with an access control list that admits only local
/// administrators and the service account itself.
/// </summary>
/// <remarks>
/// <para>
/// <b>The ACL is the pipe's access control, not a convenience.</b> A named pipe created with
/// default security is reachable by every authenticated user on the machine, and this pipe
/// carries domain creation, mailbox management and certificate operations. Restricting it at
/// creation time is what stops a low-privileged local account from administering the mail
/// server.
/// </para>
/// <para>
/// On non-Windows platforms .NET implements named pipes over Unix domain sockets, where
/// <see cref="PipeSecurity"/> does not exist. The pipe is created without an ACL there and a
/// warning is logged - development only, and never silent.
/// </para>
/// </remarks>
internal static class IpcPipeSecurity
{
    public static NamedPipeServerStream Create(
        string pipeName,
        int maxConcurrentConnections,
        ILogger logger)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);

        if (OperatingSystem.IsWindows())
        {
            return CreateSecuredWindowsPipe(pipeName, maxConcurrentConnections, logger);
        }

        logger.LogWarning(
            "Named pipe '{PipeName}' was created WITHOUT an access control list because this " +
            "platform is not Windows. Filesystem permissions on the socket are the only " +
            "protection. This configuration is for development only.",
            pipeName);

        return new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            maxConcurrentConnections,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
    }

    [SupportedOSPlatform("windows")]
    private static NamedPipeServerStream CreateSecuredWindowsPipe(
        string pipeName,
        int maxConcurrentConnections,
        ILogger logger)
    {
        PipeSecurity security = new();

        // Local administrators: the people entitled to administer the mail server.
        SecurityIdentifier administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
        security.AddAccessRule(new PipeAccessRule(
            administrators,
            PipeAccessRights.ReadWrite | PipeAccessRights.CreateNewInstance,
            AccessControlType.Allow));

        // The service's own account, so it can create further pipe instances.
        SecurityIdentifier self = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException(
                "The current Windows identity has no user SID; the pipe ACL cannot be built.");

        security.AddAccessRule(new PipeAccessRule(
            self,
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        // No rule for Authenticated Users, Everyone, or NETWORK. Their absence is the point:
        // a named pipe with default security is reachable by every authenticated local user,
        // and this one carries certificate and mailbox administration.
        //
        // Explicitly denying NETWORK is belt-and-braces - a pipe is remotely reachable over
        // SMB when the SID is permitted, and administration must be local.
        SecurityIdentifier network = new(WellKnownSidType.NetworkSid, null);
        security.AddAccessRule(new PipeAccessRule(
            network,
            PipeAccessRights.FullControl,
            AccessControlType.Deny));

        logger.LogInformation(
            "Named pipe '{PipeName}' created with an ACL granting local administrators and the " +
            "service account only; remote (NETWORK) access is explicitly denied.",
            pipeName);

        return NamedPipeServerStreamAcl.Create(
            pipeName,
            PipeDirection.InOut,
            maxConcurrentConnections,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 0,
            outBufferSize: 0,
            security);
    }
}
