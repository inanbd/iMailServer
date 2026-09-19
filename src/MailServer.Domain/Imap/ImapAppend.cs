using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using MailServer.Domain.Enums;

namespace MailServer.Domain.Imap;

/// <summary>
/// A parsed <c>APPEND</c>, up to but not including its octets.
/// </summary>
/// <remarks>
/// RFC 3501 §6.3.11's arguments are "mailbox name / OPTIONAL flag parenthesized list / OPTIONAL
/// date/time string / message literal". Everything but the last is on the command line, which is
/// why this type stops there: the octets arrive afterwards and belong to whoever owns the
/// stream.
/// </remarks>
/// <param name="Mailbox">The destination, already decoded from modified UTF-7.</param>
/// <param name="Flags">
/// The flags to set. §6.3.11: "If a flag parenthesized list is specified, the flags SHOULD be set
/// in the resulting message; otherwise, the flag list of the resulting message is set to empty by
/// default."
/// </param>
/// <param name="InternalDate">
/// The internal date to record, or null to use the clock. §6.3.11: "If a date-time is specified,
/// the internal date SHOULD be set in the resulting message; otherwise, the internal date of the
/// resulting message is set to the current date and time by default."
/// </param>
/// <param name="Literal">How many octets follow, and whether the client expects a continuation.</param>
public sealed record ImapAppendRequest(
    string Mailbox,
    MessageFlags Flags,
    DateTimeOffset? InternalDate,
    ImapLiteralSpecifier Literal);

/// <summary>Reading an <c>APPEND</c> command line.</summary>
public static class ImapAppend
{
    /// <summary>
    /// Parses everything an <c>APPEND</c> says before its octets.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Both optional arguments are genuinely optional and are told apart by shape, not by
    /// position.</b> A flag list opens with <c>(</c> and a date-time opens with <c>"</c>, so
    /// <c>APPEND box {310}</c>, <c>APPEND box (\Seen) {310}</c>, <c>APPEND box "…" {310}</c> and
    /// <c>APPEND box (\Seen) "…" {310}</c> are all conformant and all reach here.
    /// </para>
    /// <para>
    /// <b>A flag this server cannot store is dropped rather than refused</b>, exactly as
    /// <c>STORE</c> does it and for the reason RFC 3501 §7.1 gives — see
    /// <see cref="ImapStoreRequest"/>. Refusing would break a client that appends a draft with
    /// its own keyword.
    /// </para>
    /// </remarks>
    public static bool TryParse(string argument, [NotNullWhen(true)] out ImapAppendRequest? request)
    {
        ArgumentNullException.ThrowIfNull(argument);

        request = null;

        ImapAstringReader reader = new(argument);

        if (!reader.TryReadText(out string? wireName))
        {
            return false;
        }

        if (!ImapMailboxName.TryDecode(wireName, out string? mailbox))
        {
            return false;
        }

        string rest = reader.Remainder.Trim();

        MessageFlags flags = MessageFlags.None;

        if (rest.StartsWith('('))
        {
            int close = rest.IndexOf(')', StringComparison.Ordinal);

            if (close < 0)
            {
                return false;
            }

            if (!ImapStore.TryParse($"FLAGS {rest[..(close + 1)]}", out ImapStoreRequest? parsed))
            {
                return false;
            }

            flags = parsed.Flags;
            rest = rest[(close + 1)..].TrimStart();
        }

        DateTimeOffset? internalDate = null;

        if (rest.StartsWith('"'))
        {
            int close = rest.IndexOf('"', 1);

            if (close < 0)
            {
                return false;
            }

            if (!ImapInternalDate.TryParse(rest[..(close + 1)], out DateTimeOffset parsedDate))
            {
                return false;
            }

            internalDate = parsedDate;
            rest = rest[(close + 1)..].TrimStart();
        }

        if (!ImapLiteralSpecifier.TryParse(rest, out ImapLiteralSpecifier literal))
        {
            return false;
        }

        request = new ImapAppendRequest(mailbox, flags, internalDate, literal);
        return true;
    }
}
