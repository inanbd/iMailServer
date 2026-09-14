using System.Diagnostics.CodeAnalysis;

namespace MailServer.Domain.ValueObjects;

/// <summary>
/// Marker for a strongly-typed identifier wrapping a <see cref="Guid"/>.
/// </summary>
/// <remarks>
/// <para>
/// Every aggregate gets its own id type rather than sharing <see cref="Guid"/>. The cost is
/// a few lines each; the benefit is that <c>DeleteAsync(mailboxId)</c> cannot accidentally
/// be passed a <c>DomainId</c>. On a mail server that class of mistake deletes someone's
/// mail, so the compiler should be the one catching it, not a code reviewer.
/// </para>
/// <para>
/// All id types are <c>readonly record struct</c>, so strong typing costs no allocation.
/// </para>
/// <para>
/// <b>Version 7 GUIDs</b> are generated (<see cref="Guid.CreateVersion7()"/>). They are
/// time-ordered, which keeps clustered-index inserts sequential on SQL Server instead of
/// scattering them across the B-tree the way random v4 GUIDs do. That single choice is
/// worth a great deal of write throughput on the queue and message tables.
/// </para>
/// </remarks>
public interface IEntityId
{
    Guid Value { get; }
}

/// <summary>Identifies a <see cref="Entities.MailDomain"/>.</summary>
public readonly record struct DomainId(Guid Value) : IEntityId, IComparable<DomainId>
{
    public static DomainId New() => new(Guid.CreateVersion7());

    public static DomainId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    public static DomainId Parse(string value) => new(Guid.Parse(value));

    public static bool TryParse(string? value, out DomainId result)
    {
        if (Guid.TryParse(value, out Guid guid))
        {
            result = new DomainId(guid);
            return true;
        }

        result = Empty;
        return false;
    }

    public int CompareTo(DomainId other) => Value.CompareTo(other.Value);

    public override string ToString() => Value.ToString("D");
}

/// <summary>Identifies a mailbox.</summary>
public readonly record struct MailboxId(Guid Value) : IEntityId, IComparable<MailboxId>
{
    public static MailboxId New() => new(Guid.CreateVersion7());

    public static MailboxId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    public static MailboxId Parse(string value) => new(Guid.Parse(value));

    public static bool TryParse(string? value, out MailboxId result)
    {
        if (Guid.TryParse(value, out Guid guid))
        {
            result = new MailboxId(guid);
            return true;
        }

        result = Empty;
        return false;
    }

    public int CompareTo(MailboxId other) => Value.CompareTo(other.Value);

    public override string ToString() => Value.ToString("D");
}

/// <summary>Identifies an alias.</summary>
public readonly record struct AliasId(Guid Value) : IEntityId
{
    public static AliasId New() => new(Guid.CreateVersion7());

    public static AliasId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D");
}

/// <summary>Identifies an outbound queue item (one per recipient).</summary>
public readonly record struct QueueId(Guid Value) : IEntityId
{
    public static QueueId New() => new(Guid.CreateVersion7());

    public static QueueId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D");
}

/// <summary>Identifies a stored message.</summary>
public readonly record struct StoredMessageId(Guid Value) : IEntityId
{
    public static StoredMessageId New() => new(Guid.CreateVersion7());

    public static StoredMessageId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D");
}

/// <summary>Identifies a DKIM key pair.</summary>
public readonly record struct DkimKeyId(Guid Value) : IEntityId
{
    public static DkimKeyId New() => new(Guid.CreateVersion7());

    public static DkimKeyId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D");
}

/// <summary>Identifies the administrator account aggregate.</summary>
public readonly record struct AdminAccountId(Guid Value) : IEntityId
{
    public static AdminAccountId New() => new(Guid.CreateVersion7());

    public static AdminAccountId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D");
}

/// <summary>Identifies an administrative session.</summary>
public readonly record struct AdminSessionId(Guid Value) : IEntityId
{
    public static AdminSessionId New() => new(Guid.CreateVersion7());

    public static AdminSessionId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    /// <summary>
    /// Parses the session identifier carried on <c>IAdminContext.SessionIdentifier</c>.
    /// </summary>
    /// <remarks>
    /// That property is a nullable string because it also carries non-session origins for
    /// system-initiated work. Returning false rather than throwing keeps callers from having
    /// to distinguish "no session" from "malformed session" at every use site.
    /// </remarks>
    public static bool TryParseIdentifier(string? identifier, out AdminSessionId result)
    {
        if (Guid.TryParse(identifier, out Guid parsed))
        {
            result = new AdminSessionId(parsed);
            return true;
        }

        result = Empty;
        return false;
    }

    public override string ToString() => Value.ToString("D");
}

/// <summary>Identifies a security event.</summary>
public readonly record struct SecurityEventId(Guid Value) : IEntityId
{
    public static SecurityEventId New() => new(Guid.CreateVersion7());

    public static SecurityEventId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D");
}

/// <summary>Identifies an audit record.</summary>
public readonly record struct AuditId(Guid Value) : IEntityId
{
    public static AuditId New() => new(Guid.CreateVersion7());

    public static AuditId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    public override string ToString() => Value.ToString("D");
}

/// <summary>Identifies a stored certificate.</summary>
public readonly record struct CertificateId(Guid Value) : IEntityId, IComparable<CertificateId>
{
    public static CertificateId New() => new(Guid.CreateVersion7());

    public static CertificateId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    public static CertificateId Parse(string value) => new(Guid.Parse(value));

    public static bool TryParse(string? value, out CertificateId result)
    {
        if (Guid.TryParse(value, out Guid guid))
        {
            result = new CertificateId(guid);
            return true;
        }

        result = Empty;
        return false;
    }

    public int CompareTo(CertificateId other) => Value.CompareTo(other.Value);

    public override string ToString() => Value.ToString("D");
}

/// <summary>Identifies a hostname-to-certificate binding.</summary>
public readonly record struct CertificateBindingId(Guid Value) : IEntityId
{
    public static CertificateBindingId New() => new(Guid.CreateVersion7());

    public static CertificateBindingId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    public static CertificateBindingId Parse(string value) => new(Guid.Parse(value));

    public static bool TryParse(string? value, out CertificateBindingId result)
    {
        if (Guid.TryParse(value, out Guid guid))
        {
            result = new CertificateBindingId(guid);
            return true;
        }

        result = Empty;
        return false;
    }

    public override string ToString() => Value.ToString("D");
}

/// <summary>Identifies a mailbox credential.</summary>
public readonly record struct MailboxCredentialId(Guid Value) : IEntityId
{
    public static MailboxCredentialId New() => new(Guid.CreateVersion7());

    public static MailboxCredentialId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    public static bool TryParse(string? value, out MailboxCredentialId result)
    {
        if (Guid.TryParse(value, out Guid guid))
        {
            result = new MailboxCredentialId(guid);
            return true;
        }

        result = Empty;
        return false;
    }

    public override string ToString() => Value.ToString("D");
}

/// <summary>Identifies an IMAP folder within a mailbox.</summary>
public readonly record struct MailboxFolderId(Guid Value) : IEntityId
{
    public static MailboxFolderId New() => new(Guid.CreateVersion7());

    public static MailboxFolderId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    public static bool TryParse(string? value, out MailboxFolderId result)
    {
        if (Guid.TryParse(value, out Guid guid))
        {
            result = new MailboxFolderId(guid);
            return true;
        }

        result = Empty;
        return false;
    }

    public override string ToString() => Value.ToString("D");
}

/// <summary>Identifies an ACME account registration.</summary>
public readonly record struct AcmeAccountId(Guid Value) : IEntityId
{
    public static AcmeAccountId New() => new(Guid.CreateVersion7());

    public static AcmeAccountId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    public static AcmeAccountId Parse(string value) => new(Guid.Parse(value));

    public static bool TryParse(string? value, out AcmeAccountId result)
    {
        if (Guid.TryParse(value, out Guid guid))
        {
            result = new AcmeAccountId(guid);
            return true;
        }

        result = Empty;
        return false;
    }

    public override string ToString() => Value.ToString("D");
}

/// <summary>Identifies one certificate issuance attempt.</summary>
public readonly record struct AcmeOrderId(Guid Value) : IEntityId
{
    public static AcmeOrderId New() => new(Guid.CreateVersion7());

    public static AcmeOrderId Empty => new(Guid.Empty);

    public bool IsEmpty => Value == Guid.Empty;

    public static AcmeOrderId Parse(string value) => new(Guid.Parse(value));

    public static bool TryParse(string? value, out AcmeOrderId result)
    {
        if (Guid.TryParse(value, out Guid guid))
        {
            result = new AcmeOrderId(guid);
            return true;
        }

        result = Empty;
        return false;
    }

    public override string ToString() => Value.ToString("D");
}

/// <summary>
/// Correlates every log line, audit record, delivery attempt and trace entry produced while
/// handling one logical operation, across process boundaries.
/// </summary>
public readonly record struct CorrelationId
{
    private readonly string? _value;

    private CorrelationId(string value) => _value = value;

    /// <summary>The correlation token. Never empty for an initialised instance.</summary>
    public string Value => _value ?? "00000000000000000000000000";

    public static CorrelationId New() =>
        new(Guid.CreateVersion7().ToString("N")[..26]);

    /// <summary>
    /// Adopts a correlation token supplied by a caller (for example over IPC), after
    /// sanitising it. Untrusted callers must not be able to inject newlines or arbitrary
    /// length into a value that is written to every subsequent log line.
    /// </summary>
    public static CorrelationId FromExternal(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return New();
        }

        Span<char> buffer = stackalloc char[32];
        int length = 0;

        foreach (char c in value)
        {
            if (length == buffer.Length)
            {
                break;
            }

            if (char.IsAsciiLetterOrDigit(c) || c is '-' or '_')
            {
                buffer[length++] = c;
            }
        }

        return length == 0 ? New() : new CorrelationId(new string(buffer[..length]));
    }

    public override string ToString() => Value;
}
