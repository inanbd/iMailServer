using MailServer.Application.Abstractions.Security;
using MailServer.Domain.Policies;
using MailServer.Infrastructure.Configuration;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Security;

/// <summary>
/// Adapts the configuration tree to the narrow view the Application layer needs.
/// </summary>
/// <remarks>
/// The lockout policy is constructed once here rather than on each authentication attempt.
/// Building it per attempt would be wasteful, and — more importantly — its constructor
/// validates the values, so building it at startup means a nonsensical lockout configuration
/// fails fast rather than at the first sign-in attempt after a deployment.
/// </remarks>
public sealed class SecuritySettings : ISecuritySettings
{
    public SecuritySettings(IOptions<MailServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        SecurityOptions security = options.Value.Security;

        SessionIdleTimeout = TimeSpan.FromMinutes(security.AutoLockMinutes);
        SessionAbsoluteTimeout = TimeSpan.FromHours(security.SessionMaximumHours);
        MinimumPasswordLength = security.MinimumPasswordLength;

        LockoutPolicy = new LockoutPolicy(
            security.AdminLockoutThreshold,
            TimeSpan.FromMinutes(security.AdminLockoutMinutes),
            TimeSpan.FromMinutes(security.AdminLockoutMaximumMinutes),
            TimeSpan.FromMinutes(security.AdminLockoutCounterResetMinutes));
    }

    public TimeSpan SessionIdleTimeout { get; }

    public TimeSpan SessionAbsoluteTimeout { get; }

    public LockoutPolicy LockoutPolicy { get; }

    public int MinimumPasswordLength { get; }
}
