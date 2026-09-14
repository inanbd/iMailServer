namespace MailServer.Domain.Enums;

/// <summary>Lifecycle state of a mailbox.</summary>
/// <remarks>
/// Persisted as an integer, and the values match the <c>CK_Mailboxes_Status</c> check
/// constraint written in migration 0001. Adding a state means widening that constraint too.
/// </remarks>
public enum MailboxStatus
{
    /// <summary>
    /// Mail is rejected and every login is refused.
    /// </summary>
    /// <remarks>
    /// Inbound mail for a disabled mailbox is rejected at RCPT TO with a permanent failure,
    /// so the sender is told immediately rather than left believing it was delivered. That is
    /// the honest answer for an account that has been closed.
    /// </remarks>
    Disabled = 0,

    /// <summary>Normal operation.</summary>
    Active = 1,

    /// <summary>
    /// Mail is accepted and stored, but every login is refused.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The state for someone who has left, for an account under investigation, or for one
    /// whose password may be compromised. It is deliberately different from
    /// <see cref="Disabled"/>: mail keeps arriving, so nothing is lost and nobody is told the
    /// address is dead, while the credential stops working immediately.
    /// </para>
    /// <para>
    /// Rejecting mail in this state would leak the fact of the suspension to every sender,
    /// which for a compromised account is exactly the wrong signal to broadcast.
    /// </para>
    /// </remarks>
    Suspended = 2,
}

/// <summary>
/// Which access protocols a mailbox may use.
/// </summary>
/// <remarks>
/// A <c>[Flags]</c> enum kept alongside the three booleans already in the schema, because the
/// combination is what callers ask about — "may this credential submit mail" is one question,
/// not three columns.
/// </remarks>
[Flags]
public enum MailboxAccess
{
    None = 0,

    /// <summary>IMAP on 993, and the IDLE, SPECIAL-USE and UID machinery that goes with it.</summary>
    Imap = 1,

    /// <summary>
    /// POP3 on 995.
    /// </summary>
    /// <remarks>
    /// Off by default. POP3 traditionally deletes mail from the server after download, which
    /// on a multi-device account silently destroys the copy every other device was relying on.
    /// It is offered because some environments still require it, not because it is a
    /// reasonable default in 2026.
    /// </remarks>
    Pop3 = 2,

    /// <summary>Authenticated submission on 587 and 465.</summary>
    Submission = 4,

    All = Imap | Pop3 | Submission,
}

/// <summary>
/// The purpose an IMAP folder serves, from RFC 6154 SPECIAL-USE.
/// </summary>
/// <remarks>
/// <para>
/// Advertising these matters more than it looks. Without SPECIAL-USE a client guesses which
/// folder is Sent or Trash from its name, and guesses differently per client and per language
/// — which is how one account ends up with "Sent", "Sent Items" and "Gesendet" side by side,
/// each holding part of the history.
/// </para>
/// <para>
/// The attribute is what the server advertises; the folder's <i>name</i> is what the operator
/// sees, and the two are deliberately separate so a folder can be renamed without changing
/// what clients understand it to be.
/// </para>
/// </remarks>
public enum FolderSpecialUse
{
    /// <summary>An ordinary folder with no special meaning.</summary>
    None = 0,

    /// <summary>The folder new mail is delivered to. Exactly one per mailbox.</summary>
    Inbox = 1,

    /// <summary>\Sent — copies of messages the user has sent.</summary>
    Sent = 2,

    /// <summary>\Drafts — messages not yet sent.</summary>
    Drafts = 3,

    /// <summary>\Trash — deleted messages awaiting expunge.</summary>
    Trash = 4,

    /// <summary>\Junk — messages classified as spam.</summary>
    Junk = 5,

    /// <summary>\Archive — messages moved out of the inbox but kept.</summary>
    Archive = 6,
}
