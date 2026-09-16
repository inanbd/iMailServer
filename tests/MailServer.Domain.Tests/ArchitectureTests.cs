using System.Reflection;
using MailServer.Domain.Entities;

namespace MailServer.Domain.Tests;

/// <summary>
/// Enforces the Clean Architecture dependency rule mechanically.
/// </summary>
/// <remarks>
/// Layering that depends on reviewer discipline erodes. These tests make a violation a build
/// failure, which is the only kind of architectural rule that survives contact with a
/// deadline.
/// </remarks>
public sealed class ArchitectureTests
{
    /// <summary>
    /// Assemblies the Domain layer is permitted to reference.
    /// </summary>
    /// <remarks>
    /// The BCL only. Adding anything to this list should require an explicit argument in code
    /// review, which is precisely why the list is short and lives here rather than being
    /// implied by a project file.
    /// </remarks>
    private static readonly string[] PermittedDomainReferences =
    [
        "System.Runtime",
        "System.Private.CoreLib",
        "System.Collections",
        "System.Linq",
        "System.Memory",
        "System.Net.Primitives",
        "System.Runtime.InteropServices",
        "System.Text.RegularExpressions",
        "netstandard",

        // Milestone 9: DkimBodyCanonicalizer streams RFC 6376 relaxed body canonicalization
        // straight into an IncrementalHash (SHA-256). This is a BCL hashing primitive, not a
        // third-party or infrastructure dependency - the same justification SelfSignedCertificateGenerator
        // already relies on for RSA key generation elsewhere in this codebase.
        "System.Security.Cryptography",
    ];

    private static readonly string[] ForbiddenInDomain =
    [
        "Dapper",
        "Microsoft.Data.Sqlite",
        "Microsoft.Data.SqlClient",
        "MediatR",
        "FluentValidation",
        "Microsoft.Extensions",
        "Serilog",
        "PresentationFramework",
        "WindowsBase",
        "Microsoft.AspNetCore",
        "System.Data.Common",
    ];

    [Fact]
    public void The_domain_assembly_references_nothing_but_the_bcl()
    {
        Assembly domain = typeof(MailDomain).Assembly;

        string[] referenced =
        [
            .. domain.GetReferencedAssemblies()
                .Select(a => a.Name ?? string.Empty)
                .Where(n => n.Length > 0)
        ];

        string[] violations =
        [
            .. referenced.Where(name =>
                !PermittedDomainReferences.Contains(name, StringComparer.Ordinal))
        ];

        violations.ShouldBeEmpty(
            $"MailServer.Domain must reference only the BCL, but it references: " +
            $"{string.Join(", ", violations)}. The Domain layer is the innermost ring of the " +
            "Clean Architecture; a reference here inverts the dependency rule for the whole " +
            "product. If a new BCL assembly is genuinely needed, add it to " +
            $"{nameof(PermittedDomainReferences)} with a justification.");
    }

    [Fact]
    public void The_domain_assembly_references_no_forbidden_technology()
    {
        Assembly domain = typeof(MailDomain).Assembly;

        foreach (AssemblyName reference in domain.GetReferencedAssemblies())
        {
            string name = reference.Name ?? string.Empty;

            foreach (string forbidden in ForbiddenInDomain)
            {
                name.StartsWith(forbidden, StringComparison.Ordinal).ShouldBeFalse(
                    $"MailServer.Domain references '{name}'. Persistence, messaging, logging, " +
                    "validation and UI technologies must never appear in the Domain layer.");
            }
        }
    }

    [Fact]
    public void No_entity_framework_package_is_referenced_anywhere_in_the_domain()
    {
        // Rule 105: no Entity Framework. Checked here as well as by the project file, because
        // a transitive reference would not be visible in the .csproj.
        Assembly domain = typeof(MailDomain).Assembly;

        domain.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .ShouldNotContain(
                n => n.Contains("EntityFramework", StringComparison.OrdinalIgnoreCase),
                "Entity Framework is forbidden by the product's architecture rules.");
    }

    [Fact]
    public void Aggregate_roots_expose_no_public_setters()
    {
        // A public setter on an aggregate lets any caller bypass the method that enforces the
        // invariant - setting Status = Active on a domain with no mail hostname, for example.
        Assembly domain = typeof(MailDomain).Assembly;

        Type[] aggregates =
        [
            .. domain.GetTypes().Where(t =>
                t is { IsClass: true, IsAbstract: false } &&
                t.Namespace?.Contains(".Entities", StringComparison.Ordinal) == true)
        ];

        aggregates.ShouldNotBeEmpty();

        foreach (Type aggregate in aggregates)
        {
            foreach (PropertyInfo property in aggregate.GetProperties(
                BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                MethodInfo? setter = property.GetSetMethod(nonPublic: false);

                setter.ShouldBeNull(
                    $"{aggregate.Name}.{property.Name} has a public setter. Aggregate state " +
                    "must change only through methods that enforce the aggregate's invariants.");
            }
        }
    }
}
