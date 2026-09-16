using System.Security.Cryptography;

namespace MailServer.Domain.Mail;

/// <summary>
/// RFC 6376 §3.4.4 "relaxed" body canonicalization, streamed straight into a hash.
/// </summary>
/// <remarks>
/// <para>
/// The message store forbids resident whole-message reads — bodies can be tens of megabytes —
/// so this cannot buffer the body to transform it in one pass the way
/// <see cref="DkimHeaderCanonicalizer"/> does for headers. Instead it is fed the
/// body in arbitrary-sized chunks via <see cref="Append"/> and writes the canonicalized bytes
/// directly into an <see cref="IncrementalHash"/> supplied at construction. Nothing here grows
/// with the size of the body: state is a handful of booleans plus one counter.
/// </para>
/// <para>
/// The one place a naive streaming implementation would blow up is trailing blank lines — RFC
/// 6376 requires them dropped, but you cannot know a blank line is trailing until you see
/// whatever comes after it (more content, in which case it was never trailing, or the end of the
/// body, in which case it was). A message consisting of one content byte followed by ten million
/// blank lines therefore requires holding <i>something</i> for as long as those blank lines keep
/// arriving. What is held is not their bytes — a canonicalized blank line is always exactly
/// CRLF — but a count, so the held state is one <see langword="long"/> regardless of how many
/// blank lines that count represents.
/// </para>
/// <para>Not thread-safe. One instance belongs to one message.</para>
/// </remarks>
public sealed class DkimBodyCanonicalizer
{
    /// <summary>How many blank-line CRLFs are written to the hash per <see cref="IncrementalHash.AppendData(ReadOnlySpan{byte})"/> call while flushing a large run.</summary>
    private const int BlankLineFlushBatch = 128;

    private const byte Cr = (byte)'\r';
    private const byte Lf = (byte)'\n';
    private const byte Space = (byte)' ';

    private readonly IncrementalHash _hash;

    private bool _pendingCr;
    private bool _pendingWsp;
    private bool _currentLineHasContent;
    private bool _anyContentEmitted;
    private long _pendingBlankLines;
    private bool _finished;

    public DkimBodyCanonicalizer(IncrementalHash hash)
    {
        ArgumentNullException.ThrowIfNull(hash);
        _hash = hash;
    }

    /// <summary>Feeds the next chunk of raw body octets. Chunks may split lines anywhere.</summary>
    /// <remarks>
    /// Assumes CRLF line endings throughout, matching every message this server stores — see
    /// <see cref="RawMessageHeaders"/>'s equivalent remark. A stray bare LF or lone CR is treated
    /// as a line ending anyway rather than silently corrupting the hash, but is not expected in
    /// practice.
    /// </remarks>
    public void Append(ReadOnlySpan<byte> chunk)
    {
        if (_finished)
        {
            throw new InvalidOperationException("Finish() has already been called.");
        }

        foreach (byte b in chunk)
        {
            Feed(b);
        }
    }

    /// <summary>
    /// Signals the end of the body and writes whatever canonical form the trailing state
    /// resolves to. Must be called exactly once, after the last <see cref="Append"/>.
    /// </summary>
    public void Finish()
    {
        if (_finished)
        {
            throw new InvalidOperationException("Finish() has already been called.");
        }

        _finished = true;

        if (_pendingCr)
        {
            // A dangling CR with no following LF at the very end of the body. Treat it as the
            // line ending it was almost certainly meant to be rather than discarding it.
            EndLine();
        }

        _pendingWsp = false; // trailing WSP with no terminator at all is still trailing WSP.

        if (_currentLineHasContent)
        {
            // "If the body is non-empty but does not end with a CRLF, a CRLF is added."
            _hash.AppendData(CrLfSpan);
            return;
        }

        if (!_anyContentEmitted)
        {
            // A completely empty body, or one consisting only of blank lines, canonicalizes to
            // exactly one CRLF (RFC 6376 §3.4.4, the note after the algorithm).
            _hash.AppendData(CrLfSpan);
        }

        // Otherwise: real content was already emitted earlier, and every line since is blank.
        // Those blank lines are trailing and are dropped by simply never flushing them.
    }

    private static ReadOnlySpan<byte> CrLfSpan => "\r\n"u8;

    private void Feed(byte b)
    {
        if (_pendingCr)
        {
            _pendingCr = false;

            if (b == Lf)
            {
                EndLine();
                return;
            }

            // A lone CR followed by something other than LF. Treat the CR as the line ending it
            // resembles, then process this byte as the start of the next line.
            EndLine();
        }

        switch (b)
        {
            case Cr:
                _pendingCr = true;
                return;

            case Lf:
                EndLine();
                return;

            case (byte)' ':
            case (byte)'\t':
                _pendingWsp = true;
                return;

            default:
                FeedContentByte(b);
                return;
        }
    }

    private void FeedContentByte(byte b)
    {
        FlushPendingBlankLines();

        if (_pendingWsp)
        {
            _pendingWsp = false;
            _hash.AppendData(stackalloc byte[] { Space });
        }

        _hash.AppendData(stackalloc byte[] { b });
        _currentLineHasContent = true;
        _anyContentEmitted = true;
    }

    private void EndLine()
    {
        _pendingWsp = false; // WSP at the end of a line is deleted, never turned into a SP.

        if (_currentLineHasContent)
        {
            _hash.AppendData(CrLfSpan);
            _currentLineHasContent = false;
        }
        else
        {
            _pendingBlankLines++;
        }
    }

    private void FlushPendingBlankLines()
    {
        if (_pendingBlankLines == 0)
        {
            return;
        }

        Span<byte> batch = stackalloc byte[BlankLineFlushBatch * 2];
        for (int i = 0; i < batch.Length; i += 2)
        {
            batch[i] = Cr;
            batch[i + 1] = Lf;
        }

        while (_pendingBlankLines > 0)
        {
            int count = (int)Math.Min(_pendingBlankLines, BlankLineFlushBatch);
            _hash.AppendData(batch[..(count * 2)]);
            _pendingBlankLines -= count;
        }
    }
}
