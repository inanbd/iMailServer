namespace MailServer.Domain.Enums;

/// <summary>Outcome recorded against an audited administrative action.</summary>
public enum AuditResult
{
    /// <summary>The action completed.</summary>
    Success = 0,

    /// <summary>The action was attempted and failed.</summary>
    Failure = 1,

    /// <summary>The action was rejected before execution, by authorization or validation.</summary>
    Denied = 2,
}
