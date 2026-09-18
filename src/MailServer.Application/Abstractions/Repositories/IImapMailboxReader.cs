using MailServer.Domain.Imap;
using MailServer.Domain.ValueObjects;

namespace MailServer.Application.Abstractions.Repositories;

/// <summary>
/// The read side of a mailbox, for IMAP.
/// </summary>
/// <remarks>
/// <para>
/// Separate from <see cref="IDeliveryRepository"/>, which is the write side and says in its own
/// remarks that "reads for IMAP arrive in Milestone 10 and are deliberately not speculated about
/// here: an interface designed for a consumer that does not exist yet is an interface designed
/// wrongly". This is that interface, now that the consumer exists — and it is a second interface
/// rather than more methods on the first because the two have genuinely different callers. Local
/// delivery writes and never reads; an IMAP session reads constantly and writes only when a
/// client changes a flag.
/// </para>
/// <para>
/// <b>It grows one command at a time, and that is the point.</b> Only <c>SELECT</c> and
/// <c>EXAMINE</c> exist so far, so only what they need is here. Adding <c>LIST</c>'s and
/// <c>FETCH</c>'s reads now would be guessing at their shape before anything makes them prove
/// it, which is exactly the mistake the write side's remarks warn about.
/// </para>
/// <para>
/// <b>Every method takes the mailbox identity, and none of them trusts a folder id alone.</b>
/// A folder id is a value an authenticated session hands back from its own earlier
/// <c>SELECT</c> — but a session that had somehow acquired another mailbox's folder id must not
/// be able to read that folder, and the cheapest way to make that impossible is to never offer
/// a query that could. Authorisation belongs in the <c>WHERE</c> clause, not in a check a caller
/// might forget.
/// </para>
/// </remarks>
public interface IImapMailboxReader
{
    /// <summary>
    /// Finds a folder by the name a client asked for and reads what opening it requires.
    /// </summary>
    /// <remarks>
    /// One call and one query, because the count and the first-unseen position must be read at
    /// the same instant — see <see cref="ImapFolderSnapshot"/>'s remarks on why two reads that
    /// disagreed would be worse than either alone.
    /// </remarks>
    /// <param name="mailboxId">The authenticated mailbox. Scopes the search; never optional.</param>
    /// <param name="path">
    /// The mailbox name from the command, already decoded from modified UTF-7. Matched exactly,
    /// except for the inbox — see <see cref="ImapMailboxPath"/>.
    /// </param>
    /// <returns>The snapshot, or null when this mailbox has no such folder.</returns>
    Task<ImapFolderSnapshot?> OpenFolderAsync(
        MailboxId mailboxId,
        string path,
        CancellationToken cancellationToken);
}
