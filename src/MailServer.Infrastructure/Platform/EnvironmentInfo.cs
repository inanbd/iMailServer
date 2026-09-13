using System.Reflection;
using System.Runtime.InteropServices;
using MailServer.Application.Abstractions.Platform;

namespace MailServer.Infrastructure.Platform;

/// <summary>
/// Reports facts about the host machine.
/// </summary>
/// <remarks>
/// Behind an interface so that pre-flight checks, health reporting and the setup wizard can
/// be tested against a fake, rather than by mutating process-wide state in a test run.
/// </remarks>
public sealed class EnvironmentInfo : IEnvironmentInfo
{
    public EnvironmentInfo()
    {
        MachineName = Environment.MachineName;
        ProcessAccount = BuildProcessAccount();
        OperatingSystem = RuntimeInformation.OSDescription;
        RuntimeVersion = RuntimeInformation.FrameworkDescription;
        ProductVersion = ResolveProductVersion();
        IsWindows = System.OperatingSystem.IsWindows();

        // On Windows a service has no interactive session. This is how
        // Microsoft.Extensions.Hosting.WindowsServices decides too, so the two agree.
        IsWindowsService = IsWindows && !Environment.UserInteractive;
    }

    public string MachineName { get; }

    public string ProcessAccount { get; }

    public string OperatingSystem { get; }

    public string RuntimeVersion { get; }

    public string ProductVersion { get; }

    public bool IsWindows { get; }

    public bool IsWindowsService { get; }

    public long GetAvailableFreeSpaceBytes(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        try
        {
            string root = Path.GetPathRoot(Path.GetFullPath(path)) ?? path;
            DriveInfo drive = new(root);
            return drive.IsReady ? drive.AvailableFreeSpace : 0;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
        {
            // A disk-space probe must never take the server down. Zero is reported, which the
            // storage health check correctly treats as Critical and surfaces to the operator.
            return 0;
        }
    }

    private static string BuildProcessAccount()
    {
        string domain = Environment.UserDomainName;
        string user = Environment.UserName;
        return string.IsNullOrEmpty(domain) ? user : $"{domain}\\{user}";
    }

    private static string ResolveProductVersion()
    {
        Assembly assembly = typeof(EnvironmentInfo).Assembly;

        return assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? assembly.GetName().Version?.ToString()
            ?? "0.0.0";
    }
}
