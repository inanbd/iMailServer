using System.Globalization;

namespace MailServer.Domain.Pop3;

/// <summary>One message in a maildrop, as the session numbered it.</summary>
/// <param name="Number">
/// The message-number. RFC 1939 §4: "The first message in the maildrop is assigned a
/// message-number of "1", the second is assigned "2", and so on".
/// </param>
/// <param name="Uid">The folder's own identifier for the message, which POP3 never shows.</param>
/// <param name="SizeBytes">The message's size in octets, as <c>LIST</c> and <c>STAT</c> report it.</param>
/// <param name="UniqueId">The <c>UIDL</c> listing's unique-id.</param>
public sealed record Pop3MessageSlot(int Number, long Uid, long SizeBytes, string UniqueId);

/// <summary>
/// A POP3 session's view of a mailbox: the numbering, the sizes, and what this session has
/// marked for removal.
/// </summary>
/// <remarks>
/// <para>
/// <b>A snapshot, taken once when the session authenticates.</b> RFC 1939 §4: "After the POP3
/// server has opened the maildrop, it assigns a message-number to each message, and notes the
/// size of each message in octets." The numbering is positional, so it cannot be recomputed
/// mid-session without every number the client holds changing underneath it — which is exactly
/// what POP3 has no way to tell a client about.
/// </para>
/// <para>
/// <b>Deletions live here and nowhere else until <c>QUIT</c>.</b> §6: "If a session terminates
/// for some reason other than a client-issued QUIT command, the POP3 session does NOT enter the
/// UPDATE state and MUST not remove any messages from the maildrop." Marking in the database
/// instead would leave a dropped connection's marks behind, and this server's mailboxes are also
/// reachable over IMAP, where a stray <c>\Deleted</c> shows the user mail they never deleted.
/// </para>
/// </remarks>
public sealed class Pop3Maildrop
{
    private readonly List<Pop3MessageSlot> _slots = [];
    private readonly HashSet<int> _deleted = [];

    /// <summary>Builds the snapshot from the folder's messages, in the order they are numbered.</summary>
    /// <param name="uidValidity">The folder's UIDVALIDITY, which makes the unique-ids unique.</param>
    /// <param name="messages">The folder's messages, ordered as the folder orders them.</param>
    public Pop3Maildrop(long uidValidity, IEnumerable<(long Uid, long SizeBytes)> messages)
    {
        ArgumentNullException.ThrowIfNull(messages);

        int number = 1;

        foreach ((long uid, long sizeBytes) in messages)
        {
            _slots.Add(new Pop3MessageSlot(number, uid, sizeBytes, UniqueIdOf(uidValidity, uid)));
            number++;
        }
    }

    /// <summary>Every message the session knows about, deleted or not.</summary>
    public IReadOnlyList<Pop3MessageSlot> Slots => _slots;

    /// <summary>
    /// How many messages the maildrop holds, for <c>STAT</c>.
    /// </summary>
    /// <remarks>§5: "Note that messages marked as deleted are not counted in either total."</remarks>
    public long Count => _slots.Count - _deleted.Count;

    /// <summary>The maildrop's size in octets, for <c>STAT</c>. Deleted messages are not counted.</summary>
    public long TotalOctets
    {
        get
        {
            long total = 0;

            foreach (Pop3MessageSlot slot in _slots)
            {
                if (!_deleted.Contains(slot.Number))
                {
                    total += slot.SizeBytes;
                }
            }

            return total;
        }
    }

    /// <summary>The messages that are not marked, in order, for a listing.</summary>
    /// <remarks>
    /// §5 and §7 say the same thing of <c>LIST</c> and <c>UIDL</c>: "Note that messages marked
    /// as deleted are not listed."
    /// </remarks>
    public IEnumerable<Pop3MessageSlot> Live
    {
        get
        {
            foreach (Pop3MessageSlot slot in _slots)
            {
                if (!_deleted.Contains(slot.Number))
                {
                    yield return slot;
                }
            }
        }
    }

    /// <summary>The identifiers of everything this session marked, for the UPDATE state.</summary>
    public IReadOnlyList<long> MarkedUids
    {
        get
        {
            List<long> uids = [];

            foreach (Pop3MessageSlot slot in _slots)
            {
                if (_deleted.Contains(slot.Number))
                {
                    uids.Add(slot.Uid);
                }
            }

            return uids;
        }
    }

    /// <summary>Whether anything is marked.</summary>
    public bool HasMarks => _deleted.Count > 0;

    /// <summary>Whether a number has been marked for removal.</summary>
    public bool IsMarked(int number) => _deleted.Contains(number);

    /// <summary>
    /// Finds a message a command may act on.
    /// </summary>
    /// <remarks>
    /// A number that is out of range and one that has been marked are the same answer, because
    /// §5 says of every command that takes one that the argument "may NOT refer to a message
    /// marked as deleted" and §7's <c>DELE</c> adds that "Any future reference to the
    /// message-number associated with the message in a POP3 command generates an error".
    /// </remarks>
    public bool TryGet(int number, out Pop3MessageSlot slot)
    {
        slot = null!;

        if (number < 1 || number > _slots.Count || _deleted.Contains(number))
        {
            return false;
        }

        slot = _slots[number - 1];

        return true;
    }

    /// <summary>Marks a message. False when it was already marked or does not exist.</summary>
    public bool Mark(int number)
    {
        if (!TryGet(number, out _))
        {
            return false;
        }

        return _deleted.Add(number);
    }

    /// <summary>
    /// Unmarks everything, for <c>RSET</c>.
    /// </summary>
    /// <remarks>
    /// §5: "If any messages have been marked as deleted by the POP3 server, they are unmarked."
    /// </remarks>
    public void Reset() => _deleted.Clear();

    /// <summary>
    /// The unique-id a message keeps for as long as it exists.
    /// </summary>
    /// <remarks>
    /// <para>
    /// §7: "The unique-id of a message is an arbitrary server-determined string, consisting of
    /// one to 70 characters in the range 0x21 to 0x7E, which uniquely identifies a message within
    /// a maildrop and which persists across sessions. This persistence is required even if a
    /// session ends without entering the UPDATE state. The server should never reuse an unique-id
    /// in a given maildrop, for as long as the entity using the unique-id exists."
    /// </para>
    /// <para>
    /// <b>The folder's UIDVALIDITY and UID pair already satisfy every one of those clauses</b>,
    /// which is why nothing new is stored for POP3. RFC 3501 §2.3.1.1 makes a UID "a 32-bit value
    /// assigned to each message, which when used with the unique identifier validity value forms
    /// a 64-bit value that MUST NOT refer to any other message in the mailbox or any subsequent
    /// mailbox with the same name forever". The one case where a UID is reused — a folder deleted
    /// and recreated — is exactly the case where §2.3.1.1 requires a new UIDVALIDITY, so the pair
    /// stays unique where the UID alone would not.
    /// </para>
    /// <para>
    /// Two unsigned 64-bit values and a separator are at most 41 characters, all of them digits
    /// or a full stop, so the result is inside §7's length and character ranges by construction.
    /// </para>
    /// </remarks>
    public static string UniqueIdOf(long uidValidity, long uid) =>
        string.Create(CultureInfo.InvariantCulture, $"{uidValidity}.{uid}");
}
