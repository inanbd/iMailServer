using System.Reflection;

namespace MailServer.SecurityTests;

/// <summary>
/// "Never trust a pre-existing Authentication-Results or ARC-* header from an untrusted
/// upstream as a trust input." Asserted against the shipped source, not documented and hoped for.
/// </summary>
/// <remarks>
/// <para>
/// <c>docs/DMARC.md</c>'s "Inbound handling" section is explicit: "Trusting an attacker-supplied
/// <c>Authentication-Results: dmarc=pass</c> header is a complete authentication bypass, and it
/// is trivially easy to do by accident." Anyone can put whatever they like into an
/// <c>Authentication-Results</c> or <c>ARC-Seal</c>/<c>ARC-Message-Signature</c>/
/// <c>ARC-Authentication-Results</c> header of a message they send; this server's own SPF, DKIM
/// and DMARC verdicts must come only from its own DNS lookups and its own cryptographic
/// verification, never from reading one of those headers back off the wire.
/// </para>
/// <para>
/// <b>Reading an incoming <c>Authentication-Results</c> header is never legitimate</b> - this
/// server only ever composes one of its own (<c>AuthenticationResultsComposer</c>), and never
/// consumes an existing one. So the exact field name <c>"Authentication-Results"</c> must never
/// appear as a non-comment string literal in production source at all.
/// </para>
/// <para>
/// <b>Reading an incoming <c>ARC-*</c> header is legitimate in exactly one place</b>:
/// <c>ArcChain.cs</c>'s own structural, observational parsing (grouping instances, checking
/// well-formedness) - see its remarks on why that is fine and DMARC/SPF/DKIM decision-making
/// never seeing it is what matters. Every other production file is checked for the same three
/// header-name literals and must not reference them.
/// </para>
/// </remarks>
public sealed class NoUntrustedAuthenticationHeaderTrustTests
{
    /// <summary>
    /// The one file allowed to reference an ARC header name literal — its own groundwork parser,
    /// which reads these headers only to group and structurally validate them, never to feed a
    /// pass/fail decision. See <c>ArcChain.cs</c>'s own remarks.
    /// </summary>
    private const string ArcParserFileName = "ArcChain.cs";

    private static readonly string[] UntrustedHeaderNames =
    [
        "Authentication-Results",
        "ARC-Seal",
        "ARC-Message-Signature",
        "ARC-Authentication-Results",
    ];

    /// <summary>
    /// The files whose job is literally to compute SPF/DKIM/DMARC verdicts — the ones where an
    /// accidental read of an incoming trust-bearing header would be most consequential, and so
    /// are named explicitly rather than relying only on the whole-tree scan below.
    /// </summary>
    private static readonly string[] DecisionMakingFileNames =
    [
        "SpfEvaluator.cs",
        "DkimMessageVerifier.cs",
        "DmarcEvaluator.cs",
    ];

    public static TheoryData<string> ProductionSourceFiles
    {
        get
        {
            TheoryData<string> data = [];

            foreach (string file in EnumerateProductionSources())
            {
                data.Add(file);
            }

            return data;
        }
    }

    [Theory]
    [MemberData(nameof(ProductionSourceFiles))]
    public void No_production_source_file_reads_an_incoming_authentication_results_header(string file)
    {
        // ArcChain.cs's own "ARC-Authentication-Results" header-name constant contains
        // "Authentication-Results" as a substring - the same single legitimate reference the ARC
        // allowlist above already accounts for, not a second one to re-litigate here.
        AssertNoNonCommentReference(file, "Authentication-Results", allowedFileName: ArcParserFileName);
    }

    [Theory]
    [MemberData(nameof(ProductionSourceFiles))]
    public void Only_the_arc_groundwork_parser_references_an_arc_header_name(string file)
    {
        foreach (string headerName in UntrustedHeaderNames[1..])
        {
            AssertNoNonCommentReference(file, headerName, allowedFileName: ArcParserFileName);
        }
    }

    /// <summary>
    /// The decision-making evaluators, named explicitly: none may reference any of the four
    /// untrusted header names, and none may reference the ARC groundwork parser's own types
    /// (<c>ArcChain</c>, <c>ArcSet</c>) — DMARC alignment must be computed only from this
    /// server's own SPF outcome and DKIM verification, never from an ARC chain's unverified
    /// claims about either.
    /// </summary>
    [Fact]
    public void No_spf_dkim_or_dmarc_evaluator_references_arc_or_authentication_results_at_all()
    {
        List<string> evaluatorFiles = [.. EnumerateProductionSources()
            .Where(f => DecisionMakingFileNames.Contains(Path.GetFileName(f), StringComparer.Ordinal))];

        evaluatorFiles.Count.ShouldBe(DecisionMakingFileNames.Length);

        foreach (string file in evaluatorFiles)
        {
            foreach (string headerName in UntrustedHeaderNames)
            {
                AssertNoNonCommentReference(file, headerName, allowedFileName: null);
            }

            AssertNoNonCommentReference(file, "ArcChain", allowedFileName: null);
            AssertNoNonCommentReference(file, "ArcSet", allowedFileName: null);
        }
    }

    private static void AssertNoNonCommentReference(string file, string needle, string? allowedFileName)
    {
        if (allowedFileName is not null && string.Equals(Path.GetFileName(file), allowedFileName, StringComparison.Ordinal))
        {
            return;
        }

        string source = File.ReadAllText(file);

        foreach (string line in source.Split('\n'))
        {
            string trimmed = line.TrimStart();

            if (trimmed.StartsWith("//", StringComparison.Ordinal) ||
                trimmed.StartsWith("///", StringComparison.Ordinal) ||
                trimmed.StartsWith("*", StringComparison.Ordinal))
            {
                continue;
            }

            trimmed.ShouldNotContain(
                needle,
                Case.Sensitive,
                $"{Path.GetFileName(file)} references '{needle}' outside a comment. This server's " +
                "own SPF/DKIM/DMARC verdicts must never be computed from a pre-existing header " +
                "read off the wire — docs/DMARC.md's \"Inbound handling\" section explains why. " +
                "If this reference is genuinely legitimate observational parsing, it belongs in " +
                $"{ArcParserFileName} (or this test's allowlist needs updating deliberately, not " +
                "suppressing).");
        }
    }

    /// <summary>
    /// The scan must actually be scanning something, and must actually find the one legitimate
    /// reference it is designed to tolerate — otherwise a broken path calculation would make
    /// every assertion above pass vacuously.
    /// </summary>
    [Fact]
    public void The_scan_covers_the_production_source_tree_including_the_arc_parser()
    {
        List<string> files = [.. EnumerateProductionSources()];

        files.Count.ShouldBeGreaterThan(50);
        files.ShouldContain(f => f.EndsWith(ArcParserFileName, StringComparison.Ordinal));

        foreach (string fileName in DecisionMakingFileNames)
        {
            files.ShouldContain(f => f.EndsWith(fileName, StringComparison.Ordinal));
        }
    }

    /// <summary>Walks up from the test assembly to the repository root and enumerates <c>src</c>.</summary>
    private static IEnumerable<string> EnumerateProductionSources()
    {
        DirectoryInfo? directory = new(
            Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!);

        while (directory is not null &&
               !File.Exists(Path.Combine(directory.FullName, "MailServer.sln")))
        {
            directory = directory.Parent;
        }

        if (directory is null)
        {
            return [];
        }

        string src = Path.Combine(directory.FullName, "src");

        return Directory
            .EnumerateFiles(src, "*.cs", SearchOption.AllDirectories)
            .Where(static f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(static f => !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal);
    }
}
