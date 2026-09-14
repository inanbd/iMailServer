using System.Reflection;
using MailServer.Application;
using MailServer.Infrastructure;
using MailServer.Ipc.Protocol;

namespace MailServer.SecurityTests;

/// <summary>
/// Rule 105: "No certificate validation bypass". Asserted against the shipped source, not
/// documented and hoped for.
/// </summary>
/// <remarks>
/// <para>
/// The single most common route to a product with no transport security is a validation
/// bypass added during development — "just until the test certificate is sorted" — and never
/// removed. It is invisible in review because it is one line, it looks temporary, and
/// everything works afterwards.
/// </para>
/// <para>
/// These tests scan the source of every production project for the specific constructs that
/// disable validation. Source rather than IL, because the source is where a reviewer would
/// look and because a matched line can be reported with its file and content, which turns a
/// failure into a location rather than a puzzle.
/// </para>
/// <para>
/// A legitimate need for one of these patterns is a design conversation, not a suppression.
/// If one is ever genuinely required, this test is where the exception is argued for in
/// writing.
/// </para>
/// </remarks>
public sealed class NoCertificateValidationBypassTests
{
    /// <summary>Constructs that disable or weaken certificate validation.</summary>
    /// <remarks>
    /// Each is paired with what it would actually do, because a failure message naming the
    /// consequence gets fixed and one naming a regex gets suppressed.
    /// </remarks>
    private static readonly (string Pattern, string Consequence)[] ForbiddenPatterns =
    [
        // Assignment, not mention. Reading this property in order to WARN about it is exactly
        // what the SQL Server connection factory should do; setting it is the bypass.
        ("TrustServerCertificate = true",
         "accepts any certificate on the database connection, including one presented by a " +
         "machine-in-the-middle"),

        ("TrustServerCertificate=true",
         "accepts any certificate on the database connection"),

        ("ServerCertificateValidationCallback =",
         "replaces the platform's certificate validation process-wide, for every TLS client " +
         "in this process"),

        ("DangerousAcceptAnyServerCertificateValidator",
         "accepts any server certificate, which is the same as having no TLS at all"),

        ("X509VerificationFlags.AllFlags",
         "ignores every chain error, including an expired certificate and an untrusted root"),

        ("X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown",
         "ignores an unknown revocation status for a CA"),

        ("X509RevocationMode.NoCheck",
         "skips revocation checking, so a revoked certificate is still accepted"),

        ("AllowUntrustedRoot",
         "accepts a chain that does not reach a trusted root"),
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
    public void No_production_source_file_disables_certificate_validation(string file)
    {
        string source = File.ReadAllText(file);

        foreach ((string pattern, string consequence) in ForbiddenPatterns)
        {
            // Skipped inside this suite's own explanatory text and in comments that name the
            // pattern in order to forbid it — the production code deliberately documents why
            // each of these is absent.
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
                    pattern,
                    Case.Sensitive,
                    $"{Path.GetFileName(file)} contains '{pattern}', which {consequence}. " +
                    "Rule 105 forbids certificate validation bypasses. If this is genuinely " +
                    "required, it is a design decision to argue for explicitly, not a line to " +
                    "suppress this test over.");
            }
        }
    }

    /// <summary>
    /// A validation callback that returns a constant true, in any of its spellings.
    /// </summary>
    /// <remarks>
    /// Separate from the pattern list because the dangerous part is not the callback — a
    /// callback that genuinely inspects the chain is fine — but a callback whose body is
    /// <c>true</c>. This looks for the lambda forms that produce exactly that.
    /// </remarks>
    [Theory]
    [MemberData(nameof(ProductionSourceFiles))]
    public void No_production_source_file_contains_an_always_true_validation_callback(string file)
    {
        string source = File.ReadAllText(file);

        string[] alwaysTrueForms =
        [
            "=> true;",
            "=> true )",
            "return true; // validation",
        ];

        foreach (string line in source.Split('\n'))
        {
            string trimmed = line.TrimStart();

            if (trimmed.StartsWith("//", StringComparison.Ordinal) ||
                trimmed.StartsWith("///", StringComparison.Ordinal))
            {
                continue;
            }

            // Only lines that also mention certificates or SSL: plenty of legitimate code
            // returns a constant true, and flagging all of it would make this test noise that
            // gets disabled.
            bool mentionsTls =
                trimmed.Contains("ertificate", StringComparison.Ordinal) ||
                trimmed.Contains("Ssl", StringComparison.Ordinal) ||
                trimmed.Contains("sslPolicyErrors", StringComparison.OrdinalIgnoreCase);

            if (!mentionsTls)
            {
                continue;
            }

            foreach (string form in alwaysTrueForms)
            {
                trimmed.ShouldNotContain(
                    form,
                    Case.Sensitive,
                    $"{Path.GetFileName(file)} appears to contain a certificate validation " +
                    "callback that returns true unconditionally, which accepts any " +
                    "certificate and is equivalent to having no TLS.");
            }
        }
    }

    /// <summary>
    /// The scan must actually be scanning something.
    /// </summary>
    /// <remarks>
    /// Without this, a broken path calculation would make every test above pass vacuously —
    /// a green security suite that checks nothing, which is worse than a red one.
    /// </remarks>
    [Fact]
    public void The_scan_covers_the_production_source_tree()
    {
        List<string> files = [.. EnumerateProductionSources()];

        files.Count.ShouldBeGreaterThan(50);

        // The certificate code specifically, since it is what this rule is about.
        files.ShouldContain(f => f.EndsWith("CertificateManager.cs", StringComparison.Ordinal));
        files.ShouldContain(
            f => f.EndsWith("WindowsCertificateStoreReader.cs", StringComparison.Ordinal));
    }

    /// <summary>
    /// Walks up from the test assembly to the repository root and enumerates <c>src</c>.
    /// </summary>
    /// <remarks>
    /// Anchored on the solution file rather than a fixed number of <c>..</c> segments, so
    /// changing the build output layout does not silently empty the scan.
    /// </remarks>
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
