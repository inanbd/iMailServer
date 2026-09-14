namespace MailServer.Domain.Enums;

/// <summary>
/// Security-relevant occurrences, recorded separately from the administrative audit trail.
/// </summary>
/// <remarks>
/// <para>
/// Kept distinct from <c>AuditRecord</c> on purpose. The audit trail answers "who changed
/// what"; this answers "what happened to the security posture". They have different retention
/// needs, different readers, and different volumes — a brute-force run produces thousands of
/// security events and zero audit records.
/// </para>
/// <para>
/// Explicit numeric values because these are persisted.
/// </para>
/// </remarks>
public enum SecurityEventType
{
    /// <summary>An administrator signed in successfully.</summary>
    AdminSignInSucceeded = 0,

    /// <summary>An administrator sign-in was refused.</summary>
    AdminSignInFailed = 1,

    /// <summary>Repeated failures locked the account.</summary>
    AdminAccountLockedOut = 2,

    /// <summary>A sign-in was refused because the account was locked.</summary>
    AdminSignInBlockedByLockout = 3,

    /// <summary>An administrator signed out, or locked the console.</summary>
    AdminSignedOut = 4,

    /// <summary>An administrative session expired through inactivity.</summary>
    AdminSessionExpired = 5,

    /// <summary>A session was revoked, by an administrator or by a password change.</summary>
    AdminSessionRevoked = 6,

    /// <summary>The master password was created for the first time.</summary>
    MasterPasswordCreated = 7,

    /// <summary>The master password was changed by an authenticated administrator.</summary>
    MasterPasswordChanged = 8,

    /// <summary>The master password was reset using the recovery key.</summary>
    MasterPasswordResetWithRecoveryKey = 9,

    /// <summary>A recovery key was used, correctly or otherwise.</summary>
    RecoveryKeyUsed = 10,

    /// <summary>A recovery key attempt failed.</summary>
    RecoveryKeyRejected = 11,

    /// <summary>A request presented a session token that is unknown, expired or revoked.</summary>
    InvalidSessionPresented = 12,

    /// <summary>A request was refused for lack of a required permission.</summary>
    AuthorizationDenied = 13,

    /// <summary>A client violated the IPC protocol and was disconnected.</summary>
    IpcProtocolViolation = 14,

    /// <summary>A request named a command that is not in the registry.</summary>
    UnknownCommandRequested = 15,

    /// <summary>
    /// A TLS certificate was obtained from a certificate authority.
    /// </summary>
    /// <remarks>
    /// A security event rather than merely an audit record. A certificate asserts this server's
    /// identity to every client and every remote MTA, so an issuance nobody initiated is worth
    /// noticing — and certificate transparency logs make every issuance public anyway, which
    /// makes an unexplained one in this log the earlier warning.
    /// </remarks>
    CertificateIssued = 16,

    /// <summary>
    /// An attempt to obtain a certificate failed at the certificate authority.
    /// </summary>
    /// <remarks>
    /// Tracked alongside the successes because repeated failures are how an operator loses
    /// access to issuance entirely: five failed validations per hostname per hour is a limit
    /// that bites well before anyone is watching the certificate's expiry date.
    /// </remarks>
    CertificateIssuanceFailed = 17,
}
