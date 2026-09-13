namespace MailServer.Application.Abstractions.Platform;

/// <summary>
/// Facts about the machine the service is running on.
/// </summary>
/// <remarks>
/// Injected rather than read from static <c>Environment</c> members so that pre-flight
/// checks, health reporting and the setup wizard are testable without mutating process-wide
/// state.
/// </remarks>
public interface IEnvironmentInfo
{
    /// <summary>NetBIOS or DNS machine name, as recorded in audit entries.</summary>
    string MachineName { get; }

    /// <summary>Account the service process is running as.</summary>
    string ProcessAccount { get; }

    /// <summary>Operating system description.</summary>
    string OperatingSystem { get; }

    /// <summary>.NET runtime version.</summary>
    string RuntimeVersion { get; }

    /// <summary>Product version of this build.</summary>
    string ProductVersion { get; }

    /// <summary>True when running on Windows. Guards DPAPI, ACL and certificate-store paths.</summary>
    bool IsWindows { get; }

    /// <summary>True when launched by the Windows Service Control Manager.</summary>
    bool IsWindowsService { get; }

    /// <summary>Free space in bytes on the volume holding <paramref name="path"/>.</summary>
    long GetAvailableFreeSpaceBytes(string path);
}
