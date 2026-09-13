namespace MailServer.Application.Abstractions.Platform;

/// <summary>
/// The resolved, validated filesystem layout of the installation.
/// </summary>
/// <remarks>
/// <para>
/// Every path the server uses comes from here rather than from string concatenation at the
/// point of use. That gives one place to apply the containment check, one place to create
/// directories with the right ACLs, and one place to verify that staging and final storage
/// sit on the same volume - which they must, because an atomic move across volumes is a
/// copy, and a copy is not atomic.
/// </para>
/// </remarks>
public interface IServerPaths
{
    /// <summary>Root of all runtime data.</summary>
    string DataRoot { get; }

    /// <summary>Delivered mail.</summary>
    string MessagesRoot { get; }

    /// <summary>Bodies of mail awaiting outbound delivery.</summary>
    string QueueRoot { get; }

    /// <summary>Staging for in-flight DATA. Same volume as <see cref="MessagesRoot"/>.</summary>
    string TempRoot { get; }

    /// <summary>Certificates and protected key material.</summary>
    string CertificatesRoot { get; }

    /// <summary>Backups.</summary>
    string BackupsRoot { get; }

    /// <summary>Log files.</summary>
    string LogsRoot { get; }

    /// <summary>Quarantined messages.</summary>
    string QuarantineRoot { get; }

    /// <summary>Inbound DMARC and TLS-RPT reports awaiting parsing.</summary>
    string ReportsRoot { get; }

    /// <summary>Creates any missing directories and applies the required access control.</summary>
    void EnsureCreated();

    /// <summary>
    /// Resolves <paramref name="relativePath"/> under <paramref name="root"/> and verifies
    /// the result is genuinely contained within it.
    /// </summary>
    /// <remarks>
    /// Defence in depth. No component of a stored path is ever derived from user input - all
    /// identifiers are server-generated - so traversal should be impossible by construction.
    /// This check exists to catch a bug in that construction, not to sanitise input.
    /// </remarks>
    /// <exception cref="System.UnauthorizedAccessException">
    /// The resolved path escapes <paramref name="root"/>.
    /// </exception>
    string ResolveContained(string root, string relativePath);
}
