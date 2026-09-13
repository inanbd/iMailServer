namespace MailServer.Domain.ValueObjects;

/// <summary>
/// What a request declares as safe to write to the audit trail.
/// </summary>
/// <remarks>
/// <para>
/// This type is the mechanism behind brief rule 97, "Never audit secret values". The audit
/// pipeline behavior does not reflect over the request object and does not serialise it.
/// It calls <c>IAuditableRequest.DescribeForAudit()</c> and stores only what comes back.
/// </para>
/// <para>
/// The consequence is that adding a new secret-bearing field to a command cannot
/// accidentally start logging that secret: the descriptor is written by hand, so a new
/// field is absent from the audit trail until somebody deliberately adds it.
/// </para>
/// </remarks>
public sealed record AuditDescriptor
{
    public AuditDescriptor(string action, string targetType, string? targetIdentifier, string? detail = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetType);

        Action = action;
        TargetType = targetType;
        TargetIdentifier = targetIdentifier;
        Detail = detail;
    }

    /// <summary>Stable action name, e.g. <c>Domain.Create</c>.</summary>
    public string Action { get; }

    /// <summary>Type of the object acted upon.</summary>
    public string TargetType { get; }

    /// <summary>Identifier of the object acted upon.</summary>
    public string? TargetIdentifier { get; }

    /// <summary>Optional extra context. Must never contain a secret.</summary>
    public string? Detail { get; }
}
