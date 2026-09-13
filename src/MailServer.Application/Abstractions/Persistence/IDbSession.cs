using System.Data.Common;

namespace MailServer.Application.Abstractions.Persistence;

/// <summary>
/// A unit of database work: an open connection plus the transaction enlisted on it, if any.
/// </summary>
public interface IDbSession : IAsyncDisposable
{
    /// <summary>The open connection.</summary>
    DbConnection Connection { get; }

    /// <summary>The enlisted transaction, or null when this session is not transactional.</summary>
    DbTransaction? Transaction { get; }

    /// <summary>True when a transaction is enlisted.</summary>
    bool IsTransactional { get; }
}

/// <summary>
/// Exposes the ambient session established by <see cref="ITransactionManager"/>.
/// </summary>
/// <remarks>
/// <para>
/// Registered as <b>scoped</b>, never static. Brief rule 111 forbids static mutable state,
/// and an <c>AsyncLocal</c> ambient transaction is exactly the kind of invisible coupling
/// that makes concurrency bugs unreproducible. A scoped service makes the lifetime explicit
/// and visible in the container.
/// </para>
/// <para>
/// Repositories consult this: if a transaction is in progress they join it, otherwise they
/// open and dispose their own short-lived connection. That is what lets a single repository
/// method be called both inside and outside a transaction without the caller caring.
/// </para>
/// </remarks>
public interface IAmbientDbSession
{
    /// <summary>The ambient session, or null when no transaction is in progress.</summary>
    IDbSession? Current { get; }
}
