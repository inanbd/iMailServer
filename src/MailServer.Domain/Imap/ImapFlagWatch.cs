using MailServer.Domain.Enums;

namespace MailServer.Domain.Imap;

/// <summary>One message's flags, as the folder holds them at one instant.</summary>
/// <remarks>
/// The two columns a flag poll reads and nothing else. Deliberately not
/// <see cref="ImapMessageSummary"/>, which also carries <c>INTERNALDATE</c> and the message's
/// size: those come from a join onto <c>Messages</c>, and a poll that dragged them along would
/// turn the cheapest read in the IMAP layer into the most expensive one for values it never
/// looks at.
/// </remarks>
/// <param name="Uid">The message's unique identifier, stable for the folder's life.</param>
/// <param name="Flags">Its flags as stored.</param>
public readonly record struct ImapFlagState(long Uid, MessageFlags Flags);

/// <summary>The two numbers an idling connection reads every poll.</summary>
/// <remarks>
/// <para>
/// Read together in one statement, because the pair is used to decide one thing — whether
/// anything has happened — and two statements could straddle a change and answer "no" about a
/// folder that had both gained a message and had a flag set.
/// </para>
/// <para>
/// A folder that has been deleted out from under the session reports zero and zero rather than
/// nothing. There is no "the folder is gone" case for this type to carry: RFC 3501 §6.3.4 lets
/// another session <c>DELETE</c> a mailbox this one has selected, and what the idling client
/// sees then is a mailbox that has become empty — which is what the numbers already say.
/// </para>
/// </remarks>
/// <param name="ExistsCount">How many messages the folder holds — §7.3.1's <c>EXISTS</c>.</param>
/// <param name="FlagsModSeq">
/// The folder's flag-change counter, bumped by every write that changes a message's flags. Only
/// ever compared with a previously read value; its absolute magnitude means nothing.
/// </param>
public readonly record struct ImapFolderPoll(long ExistsCount, long FlagsModSeq);

/// <summary>One untagged <c>FETCH</c> an idling connection owes its client.</summary>
/// <param name="SequenceNumber">
/// The message's position <i>in the client's own numbering</i>, from 1. See
/// <see cref="ImapFlagWatch"/> on why that is not necessarily its position in the folder.
/// </param>
/// <param name="Uid">The message's unique identifier.</param>
/// <param name="Flags">The flags the folder now holds, which is what §6.4.6 asks to be reported.</param>
public readonly record struct ImapFlagChange(long SequenceNumber, long Uid, MessageFlags Flags);

/// <summary>
/// Watches a selected folder's flags on behalf of one client, and says what it has not been told.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this discharges.</b> RFC 3501 §6.4.6: "Regardless of whether or not the
/// <c>.SILENT</c> suffix was used, the server SHOULD send an untagged FETCH response if a change
/// to a message's flags from an external source is observed. The intent is that the status of
/// the flags is determinate without a race condition." A server that only ever reports flags in
/// answer to a command leaves a client that is sitting in <c>IDLE</c> showing a message as
/// unread minutes after another client read it.
/// </para>
/// <para>
/// <b>"External" needs no test here.</b> The watch only runs while the connection is idling, and
/// §3 of RFC 2177 forbids the client from sending anything but <c>DONE</c> then — so every
/// change this class can possibly see was made by somebody else. Distinguishing this session's
/// own writes would be dead code.
/// </para>
/// <para>
/// <b>The list this holds is the client's, not the folder's, and the difference is the whole
/// design.</b> A message sequence number is a position in what the client believes the folder
/// holds (§2.3.1.2), and the two part company the moment another session expunges something:
/// §7.4.1 forbids renumbering a client that has not been sent the <c>EXPUNGE</c> lines, and this
/// server deliberately does not send them from a poll — see
/// <c>ImapConnectionHandler.IdleAsync</c>. So positions are read out of this list, which is
/// extended only in step with what the client has been told, and never out of the folder as it
/// stands.
/// </para>
/// <para>
/// <b>Which is why an expunge stops the list growing rather than stopping the watch.</b> Once a
/// message the client still counts has gone, this session's view and the client's have diverged
/// below that point — but every entry already in the list is still the client's own entry at the
/// client's own position, so reporting those remains exactly right. What can no longer be known
/// is which message the client would put at a <i>new</i> position, so the list stops being
/// extended and positions past its end are never reported. The client learns the truth on its
/// next command, which is late but never wrong.
/// </para>
/// <para>
/// <b>Nothing is reported at a position the client has not been told exists.</b> A folder that
/// grew between <c>SELECT</c> and <c>IDLE</c> is watched from its true size, so the list can be
/// longer than the client's count for one poll; those entries are recorded silently and become
/// reportable once an <c>EXISTS</c> has covered them. A <c>FETCH</c> for a position the client
/// does not have is a response about a message it cannot identify.
/// </para>
/// <para>
/// <b><c>\Recent</c> needs no exclusion.</b> RFC 3501 §2.3.2 makes it session-scoped rather than
/// stored, and this product never sets it — see <see cref="MessageFlags.Recent"/> — so it cannot
/// be the difference this class finds.
/// </para>
/// <para>Not thread-safe. One watch belongs to one connection, like the session that holds it.</para>
/// </remarks>
public sealed class ImapFlagWatch
{
    /// <summary>
    /// The messages the client counts, in the client's order, with the flags it was last told.
    /// </summary>
    private readonly List<ImapFlagState> _known;

    private ImapFlagWatch(List<ImapFlagState> known, long flagsModSeq)
    {
        _known = known;
        ObservedModSeq = flagsModSeq;
        ObservedCount = known.Count;
    }

    /// <summary>Begins watching a folder from what it holds now.</summary>
    /// <remarks>
    /// The starting point is the folder's present state rather than an empty list, because a
    /// change is only news if it happened after the client last had the truth. Seeding empty
    /// would make the first poll report every message in the folder as changed.
    /// </remarks>
    /// <param name="folder">Every message in the folder, ascending by UID.</param>
    /// <param name="flagsModSeq">The folder's flag-change counter as it stands.</param>
    public static ImapFlagWatch Start(IReadOnlyList<ImapFlagState> folder, long flagsModSeq)
    {
        ArgumentNullException.ThrowIfNull(folder);

        return new ImapFlagWatch([.. folder], flagsModSeq);
    }

    /// <summary>The folder's flag-change counter as of the last look.</summary>
    public long ObservedModSeq { get; private set; }

    /// <summary>How many messages the folder held as of the last look.</summary>
    public long ObservedCount { get; private set; }

    /// <summary>
    /// Whether anything has happened that could need reporting, from two cheap numbers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The point of asking is to avoid reading the folder's rows on a timer. A flag change moves
    /// the counter; an arrival or an expunge moves the count. Between them those cover every
    /// event this watch reacts to, so a folder that nothing has happened to costs one aggregate
    /// query per poll however many messages it holds.
    /// </para>
    /// <para>
    /// <b>The count is watched as well as the counter, and not only for arrivals.</b> An expunge
    /// moves no flag and so moves no counter, and a watch that learned of it late would go on
    /// extending its list past a message that is no longer there.
    /// </para>
    /// </remarks>
    /// <param name="messageCount">How many messages the folder holds now.</param>
    /// <param name="flagsModSeq">The folder's flag-change counter now.</param>
    public bool NeedsLook(long messageCount, long flagsModSeq) =>
        messageCount != ObservedCount || flagsModSeq != ObservedModSeq;

    /// <summary>
    /// Looks at the folder and returns the untagged <c>FETCH</c> responses the client is owed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Call this after any <c>EXISTS</c> for the same look has been written, so that
    /// <paramref name="reportedExists"/> already covers what has just arrived. Nothing breaks if
    /// it does not — a position the client has not been told about is simply held back to the
    /// next look — but the client hears about a new message and its flags one poll apart.
    /// </para>
    /// <para>
    /// The returned changes are in ascending position order, which is also ascending UID order.
    /// </para>
    /// </remarks>
    /// <param name="folder">Every message in the folder, ascending by UID.</param>
    /// <param name="flagsModSeq">The folder's flag-change counter as of this read.</param>
    /// <param name="reportedExists">How many messages the client has been told the folder holds.</param>
    public IReadOnlyList<ImapFlagChange> Observe(
        IReadOnlyList<ImapFlagState> folder,
        long flagsModSeq,
        long reportedExists)
    {
        ArgumentNullException.ThrowIfNull(folder);
        ArgumentOutOfRangeException.ThrowIfNegative(reportedExists);

        ObservedModSeq = flagsModSeq;
        ObservedCount = folder.Count;

        Dictionary<long, MessageFlags> present = new(folder.Count);

        foreach (ImapFlagState state in folder)
        {
            present[state.Uid] = state.Flags;
        }

        List<ImapFlagChange> changes = [];

        for (int index = 0; index < _known.Count; index++)
        {
            ImapFlagState mine = _known[index];

            if (!present.TryGetValue(mine.Uid, out MessageFlags now))
            {
                // Expunged by another session. The client still counts it, so its position
                // stands and the entry stays; there is simply nothing to say about it. That the
                // entry stays is also what stops the list growing - see Extend.
                continue;
            }

            if (now == mine.Flags)
            {
                continue;
            }

            _known[index] = mine with { Flags = now };

            // Only positions the client has been told exist. The loop is already bounded by
            // what this watch knows, so that half of the question needs no test of its own.
            if (index < reportedExists)
            {
                changes.Add(new ImapFlagChange(index + 1, mine.Uid, now));
            }
        }

        Extend(folder);

        return changes;
    }

    /// <summary>
    /// Adopts messages that have arrived since the last look, if the client's numbering still
    /// matches the folder's.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The prefix test is what licenses the adoption. Sequence numbers are positions, so a new
    /// message's position is only known to be its position in the folder while every earlier
    /// position agrees — and the moment one does not, no arithmetic recovers which message the
    /// client would count where.
    /// </para>
    /// <para>
    /// <b>Re-derived on every look rather than remembered.</b> A flag saying "this watch gave up
    /// extending" would be a second statement of something the list already says: once a message
    /// the client counts has gone, it is still in this list and no longer in the folder, and
    /// UIDs are "strictly increasing within the folder … never reused, never reordered" — the
    /// schema says so in as many words — so it can never come back and the test can never pass
    /// again. Two ways to know the same thing is one way to know it twice differently.
    /// </para>
    /// <para>
    /// The test is by UID rather than by count, which also catches a folder that has both gained
    /// and lost a message since the last look and so is exactly as long as it was.
    /// </para>
    /// </remarks>
    private void Extend(IReadOnlyList<ImapFlagState> folder)
    {
        for (int index = 0; index < _known.Count; index++)
        {
            if (index >= folder.Count || folder[index].Uid != _known[index].Uid)
            {
                return;
            }
        }

        for (int index = _known.Count; index < folder.Count; index++)
        {
            _known.Add(folder[index]);
        }
    }
}
