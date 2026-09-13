using MailServer.Domain.Policies;

namespace MailServer.Application.Abstractions.Security;

/// <summary>
/// The security settings the Application layer needs, bound from configuration.
/// </summary>
/// <remarks>
/// A narrow interface rather than injecting the whole options tree, so handlers depend on the
/// five values they use rather than on the shape of <c>appsettings.json</c>. It also keeps the
/// Application layer free of any configuration-binding package.
/// </remarks>
public interface ISecuritySettings
{
    /// <summary>Idle period after which a session ends.</summary>
    TimeSpan SessionIdleTimeout { get; }

    /// <summary>Hard lifetime of a session regardless of activity.</summary>
    TimeSpan SessionAbsoluteTimeout { get; }

    /// <summary>The configured lockout policy.</summary>
    LockoutPolicy LockoutPolicy { get; }

    /// <summary>Minimum acceptable master password length.</summary>
    int MinimumPasswordLength { get; }
}

/// <summary>
/// Generates recovery keys.
/// </summary>
/// <remarks>
/// Behind an interface so tests can make key generation deterministic. The production
/// implementation uses a cryptographic RNG; a test that had to guess a random key could not
/// verify the recovery flow at all.
/// </remarks>
public interface IRecoveryKeyGenerator
{
    /// <summary>
    /// Generates a new recovery key in unformatted form.
    /// </summary>
    /// <remarks>
    /// Formatting for display is applied separately by
    /// <see cref="MailServer.Domain.Policies.PasswordPolicy.FormatRecoveryKey"/>, so the value
    /// that gets hashed is always the normalised one and a user re-typing it with or without
    /// the hyphens both work.
    /// </remarks>
    string Generate();
}
