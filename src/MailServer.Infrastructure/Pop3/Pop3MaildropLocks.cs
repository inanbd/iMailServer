using System.Collections.Concurrent;
using MailServer.Domain.ValueObjects;

namespace MailServer.Infrastructure.Pop3;

/// <summary>
/// The exclusive-access lock RFC 1939 §4 requires on a maildrop.
/// </summary>
/// <remarks>
/// <para>
/// §4: "the POP3 server then acquires an exclusive-access lock on the maildrop, as necessary to
/// prevent messages from being modified or removed before the session enters the UPDATE state.
/// […] If the maildrop cannot be opened for some reason (for example, a lock can not be
/// acquired […]), the POP3 server responds with a negative status indicator."
/// </para>
/// <para>
/// <b>Why POP3 needs this and IMAP does not.</b> A POP3 session numbers its messages once, at
/// login, and the numbers are positions: message 3 is the third message. There is no response in
/// the protocol that can tell a client the numbering has changed, so a second session removing a
/// message would silently make the first session's <c>DELE 3</c> delete somebody else's mail.
/// IMAP has <c>EXPUNGE</c> for precisely this and POP3 has nothing.
/// </para>
/// <para>
/// <b>The lock is process-local, and that is a documented limit rather than an oversight.</b> It
/// is held in memory by one server process, so two processes serving the same database would
/// each grant it. Making it durable would mean a row that outlives a crashed session and a
/// timeout to release it — a lock that can be held by a process that no longer exists is worse
/// than one that is only as strong as the deployment. <c>docs/POP3.md</c> records it, and the
/// single-process deployment this server is built for is the case it is correct in.
/// </para>
/// </remarks>
public interface IPop3MaildropLocks
{
    /// <summary>
    /// Takes the lock for a mailbox, or fails if another session holds it.
    /// </summary>
    /// <returns>A lease to dispose when the session ends, or null when the lock is held.</returns>
    IDisposable? TryAcquire(MailboxId mailbox);
}

/// <summary>An in-memory implementation of <see cref="IPop3MaildropLocks"/>.</summary>
/// <remarks>
/// Registered as a singleton: a lock held per scope would be no lock at all, because every
/// connection gets its own scope.
/// </remarks>
public sealed class Pop3MaildropLocks : IPop3MaildropLocks
{
    private readonly ConcurrentDictionary<Guid, byte> _held = new();

    /// <summary>How many maildrops are locked. For tests and diagnostics.</summary>
    public int Count => _held.Count;

    public IDisposable? TryAcquire(MailboxId mailbox) =>
        _held.TryAdd(mailbox.Value, 0) ? new Lease(this, mailbox.Value) : null;

    private void Release(Guid mailbox) => _held.TryRemove(mailbox, out _);

    /// <summary>
    /// One session's hold on a maildrop.
    /// </summary>
    /// <remarks>
    /// Disposing twice releases once. A connection's cleanup path can run from more than one
    /// place — an ordinary <c>QUIT</c>, a dropped socket, a shutdown — and a lease that released
    /// a lock somebody else had since taken would be worse than one that leaked.
    /// </remarks>
    private sealed class Lease(Pop3MaildropLocks owner, Guid mailbox) : IDisposable
    {
        private bool _released;

        public void Dispose()
        {
            if (_released)
            {
                return;
            }

            _released = true;
            owner.Release(mailbox);
        }
    }
}
