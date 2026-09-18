using MailServer.Domain.Imap;
using Shouldly;
using Xunit;

namespace MailServer.Imap.Tests;

public sealed class ZzTempProbeTests
{
    [Theory]
    [InlineData("BODY[HEADER.FIELDS (DATE FROM)]")]
    [InlineData("(UID RFC822.SIZE FLAGS BODY.PEEK[HEADER.FIELDS (From To)])")]
    [InlineData("(FLAGS BODY[HEADER.FIELDS (DATE)])")]
    [InlineData("BODY[HEADER.FIELDS.NOT (DATE FROM)]")]
    public void Probe_request(string text)
    {
        bool ok = ImapFetchItems.TryParseRequest(text, out System.Collections.Generic.IReadOnlyList<ImapFetchItem> items);
        ok.ShouldBeTrue($"TryParseRequest({text}) returned false; items=[{string.Join(",", items)}]");
    }

    [Theory]
    [InlineData("BODY[]")]
    [InlineData("BODY[TEXT]")]
    [InlineData("BODY[]<0.100>")]
    public void Probe_control(string text) =>
        ImapFetchItems.TryParseRequest(text, out _).ShouldBeTrue();
}
