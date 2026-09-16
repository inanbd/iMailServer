using MailServer.Domain.ValueObjects;
using MailServer.Infrastructure.Dmarc;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Infrastructure.Tests.Dmarc;

/// <summary>
/// Confirms the real embedded Public Suffix List snapshot (not a hand-written fixture) loads and
/// resolves correctly - <see cref="Authentication.Tests.PublicSuffixListTests"/> exercises the
/// parsing/lookup algorithm itself against a small synthetic list.
/// </summary>
public class PublicSuffixListLoaderTests
{
    private static readonly PublicSuffixList List =
        new PublicSuffixListLoader(NullLogger<PublicSuffixListLoader>.Instance).List;

    [Fact]
    public void Loads_a_snapshot_with_a_recorded_version_date()
    {
        List.SnapshotDateUtc.ShouldNotBeNull();
    }

    [Fact]
    public void Caches_the_parsed_list_across_repeated_access()
    {
        PublicSuffixListLoader loader = new(NullLogger<PublicSuffixListLoader>.Instance);
        loader.List.ShouldBeSameAs(loader.List);
    }

    [Theory]
    [InlineData("example.com", "example.com")]
    [InlineData("mail.example.com", "example.com")]
    [InlineData("example.co.uk", "example.co.uk")]
    [InlineData("www.example.co.uk", "example.co.uk")]
    [InlineData("something.github.io", "something.github.io")]
    public void Resolves_well_known_real_world_organizational_domains(string input, string expected)
    {
        List.GetOrganizationalDomain(DomainName.Parse(input)).Value.ShouldBe(expected);
    }
}
