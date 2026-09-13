using MailServer.Domain.Enums;
using MailServer.Domain.Primitives;
using MailServer.Domain.ValueObjects;

namespace MailServer.Domain.Entities;

/// <summary>
/// An immutable record of a privileged administrative action.
/// </summary>
/// <remarks>
/// <para>
/// Audit records are append-only. There is no mutator on this type and no UPDATE statement
/// against the table; an audit trail that can be edited is not an audit trail.
/// </para>
/// <para>
/// <b>Secrets are never recorded.</b> The description is supplied by the request itself via
/// <c>IAuditableRequest.DescribeForAudit()</c> rather than produced by serialising the
/// request object. A generic "serialise and store" audit behavior would faithfully write
/// new mailbox passwords and imported certificate passphrases into this table.
/// </para>
/// </remarks>
public sealed class AuditRecord : Entity<AuditId>
{
    public AuditRecord(
        AuditId id,
        DateTimeOffset timestampUtc,
        string administrator,
        string action,
        string targetType,
        string? targetIdentifier,
        AuditResult result,
        string? detail,
        string machineName,
        string? sessionIdentifier,
        CorrelationId correlationId) : base(id)
    {
        TimestampUtc = timestampUtc;
        Administrator = administrator;
        Action = action;
        TargetType = targetType;
        TargetIdentifier = targetIdentifier;
        Result = result;
        Detail = detail;
        MachineName = machineName;
        SessionIdentifier = sessionIdentifier;
        CorrelationId = correlationId;
    }

    /// <summary>When the action was attempted.</summary>
    public DateTimeOffset TimestampUtc { get; }

    /// <summary>Who attempted it. A Windows account name, or the built-in administrator.</summary>
    public string Administrator { get; }

    /// <summary>Stable action name, e.g. <c>Domain.Create</c>.</summary>
    public string Action { get; }

    /// <summary>Type of the object acted upon, e.g. <c>MailDomain</c>.</summary>
    public string TargetType { get; }

    /// <summary>Identifier of the object acted upon, e.g. <c>example.com</c>.</summary>
    public string? TargetIdentifier { get; }

    /// <summary>Outcome.</summary>
    public AuditResult Result { get; }

    /// <summary>
    /// Human-readable detail. Contains only values the originating request explicitly
    /// declared safe to record.
    /// </summary>
    public string? Detail { get; }

    /// <summary>Machine on which the action was performed.</summary>
    public string MachineName { get; }

    /// <summary>Administrative session, where one applies.</summary>
    public string? SessionIdentifier { get; }

    /// <summary>Joins this record to the log lines and message traces for the same operation.</summary>
    public CorrelationId CorrelationId { get; }

    public static AuditRecord Create(
        DateTimeOffset timestampUtc,
        string administrator,
        string action,
        string targetType,
        string? targetIdentifier,
        AuditResult result,
        string? detail,
        string machineName,
        string? sessionIdentifier,
        CorrelationId correlationId) =>
        new(AuditId.New(),
            timestampUtc,
            administrator,
            action,
            targetType,
            targetIdentifier,
            result,
            detail,
            machineName,
            sessionIdentifier,
            correlationId);
}
