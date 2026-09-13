using MailServer.Application.Abstractions.Platform;
using MailServer.Infrastructure.Configuration;
using MailServer.Infrastructure.Platform;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace MailServer.Infrastructure.Tests;

public sealed class ServerPathsTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "aethermail-path-tests",
        Guid.NewGuid().ToString("N"));

    private readonly ServerPaths _paths;

    public ServerPathsTests()
    {
        MailServerOptions options = new() { Storage = new StorageOptions { DataRoot = _root } };

        _paths = new ServerPaths(
            Options.Create(options),
            NullLogger<ServerPaths>.Instance);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    [Fact]
    public void Every_managed_directory_is_created()
    {
        _paths.EnsureCreated();

        foreach (string directory in _paths.AllRoots())
        {
            Directory.Exists(directory).ShouldBeTrue($"{directory} should have been created.");
        }
    }

    [Fact]
    public void EnsureCreated_is_idempotent()
    {
        _paths.EnsureCreated();
        _paths.EnsureCreated();

        Directory.Exists(_paths.MessagesRoot).ShouldBeTrue();
    }

    [Fact]
    public void Staging_and_message_storage_share_a_volume()
    {
        // They must, because File.Move across volumes is a copy, and a copy is not atomic.
        // A partially written .eml appearing under Messages/ is exactly what atomic writes
        // exist to prevent.
        _paths.EnsureCreated();

        Path.GetPathRoot(_paths.TempRoot).ShouldBe(Path.GetPathRoot(_paths.MessagesRoot));
    }

    [Theory]
    [InlineData("2026/09/ab/cd/message.eml")]
    [InlineData("simple.eml")]
    [InlineData("a/b/c/d/e/f.eml")]
    public void A_legitimate_relative_path_resolves_under_its_root(string relative)
    {
        _paths.EnsureCreated();

        string resolved = _paths.ResolveContained(_paths.MessagesRoot, relative);

        resolved.ShouldStartWith(_paths.MessagesRoot);
    }

    [Theory]
    [InlineData("../escaped.eml")]
    [InlineData("../../escaped.eml")]
    [InlineData("subdir/../../escaped.eml")]
    [InlineData("a/b/../../../../escaped.eml")]
    public void A_traversal_attempt_is_refused(string relative)
    {
        // Defence in depth. Every stored path is built from server-generated identifiers, so
        // reaching this check means a bug in path construction rather than hostile input -
        // which is precisely why it throws loudly instead of silently sanitising.
        _paths.EnsureCreated();

        Should.Throw<UnauthorizedAccessException>(
            () => _paths.ResolveContained(_paths.MessagesRoot, relative));
    }

    [Fact]
    public void An_absolute_path_escaping_the_root_is_refused()
    {
        _paths.EnsureCreated();

        string elsewhere = Path.Combine(Path.GetTempPath(), "definitely-elsewhere.eml");

        Should.Throw<UnauthorizedAccessException>(
            () => _paths.ResolveContained(_paths.MessagesRoot, elsewhere));
    }

    [Fact]
    public void A_sibling_directory_with_the_root_as_a_prefix_is_refused()
    {
        // The classic prefix bug: "…/Messages-evil" starts with "…/Messages". Only the
        // trailing separator in the comparison distinguishes them.
        _paths.EnsureCreated();

        Should.Throw<UnauthorizedAccessException>(
            () => _paths.ResolveContained(_paths.MessagesRoot, "../Messages-evil/x.eml"));
    }

    [Fact]
    public void The_root_itself_resolves_successfully()
    {
        _paths.EnsureCreated();

        _paths.ResolveContained(_paths.MessagesRoot, ".").ShouldBe(_paths.MessagesRoot);
    }

    [Fact]
    public void Paths_are_absolute_even_when_configured_relatively()
    {
        // The Windows SCM gives a service no working directory of its own, so a relative data
        // root would resolve under system32.
        MailServerOptions options = new() { Storage = new StorageOptions { DataRoot = "RelativeData" } };

        ServerPaths paths = new(Options.Create(options), NullLogger<ServerPaths>.Instance);

        Path.IsPathRooted(paths.DataRoot).ShouldBeTrue();
        Path.IsPathRooted(paths.MessagesRoot).ShouldBeTrue();
    }
}
