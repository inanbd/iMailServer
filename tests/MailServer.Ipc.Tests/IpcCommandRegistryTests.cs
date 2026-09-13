using MailServer.Application.Abstractions.Messaging;
using MailServer.Domain.Enums;
using MailServer.Ipc.Protocol;
using MediatR;

namespace MailServer.Ipc.Tests;

public sealed class IpcCommandRegistryTests
{
    [Fact]
    public void The_default_registry_builds_without_error()
    {
        // The constructor validates every entry. If a command were registered without
        // declaring a required permission, this would throw - which is exactly the point:
        // the failure happens at startup, not in production.
        IpcCommandRegistry registry = new();

        registry.Commands.ShouldNotBeEmpty();
    }

    [Theory]
    [InlineData("Domains.List")]
    [InlineData("Domains.Get")]
    [InlineData("Domains.Create")]
    [InlineData("Domains.Update")]
    [InlineData("Domains.SetStatus")]
    [InlineData("Domains.Delete")]
    [InlineData("Monitoring.Dashboard")]
    public void Every_documented_command_resolves(string name)
    {
        IpcCommandRegistry registry = new();

        registry.TryResolve(name, out IpcCommandDescriptor? descriptor).ShouldBeTrue();
        descriptor!.Name.ShouldBe(name);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Nonexistent.Command")]
    [InlineData("System.Diagnostics.Process")]
    [InlineData("MailServer.Application.Domains.Commands.CreateDomainCommand, MailServer.Application")]
    public void An_unregistered_name_does_not_resolve(string? name)
    {
        // The last two cases matter most. If the server resolved a wire string through
        // Type.GetType, anyone who could reach the pipe could instantiate arbitrary types in
        // the service process - a remote code execution primitive. The registry is an
        // allow-list, so an assembly-qualified type name is just an unknown command.
        IpcCommandRegistry registry = new();

        registry.TryResolve(name, out IpcCommandDescriptor? descriptor).ShouldBeFalse();
        descriptor.ShouldBeNull();
    }

    [Fact]
    public void Resolution_is_case_sensitive()
    {
        // Case-insensitive matching would let the same operation arrive under many spellings,
        // which makes audit-log analysis and per-command rate limiting unnecessarily fuzzy.
        IpcCommandRegistry registry = new();

        registry.TryResolve("domains.create", out _).ShouldBeFalse();
        registry.TryResolve("DOMAINS.CREATE", out _).ShouldBeFalse();
        registry.TryResolve("Domains.Create", out _).ShouldBeTrue();
    }

    [Fact]
    public void Every_registered_request_declares_a_required_permission()
    {
        IpcCommandRegistry registry = new();

        foreach (IpcCommandDescriptor descriptor in registry.Commands)
        {
            typeof(IAuthorizedRequest).IsAssignableFrom(descriptor.RequestType).ShouldBeTrue(
                $"{descriptor.Name} maps to {descriptor.RequestType.Name}, which does not " +
                "declare a required permission. The authorization behavior would then have " +
                "nothing to enforce and the command would be effectively public.");
        }
    }

    private sealed record UnprotectedCommand : ICommand<Unit>;

    [Fact]
    public void Registering_a_command_without_authorization_fails_at_construction()
    {
        InvalidOperationException ex = Should.Throw<InvalidOperationException>(() =>
            new IpcCommandRegistry(
            [
                new IpcCommandDescriptor("Test.Unprotected", typeof(UnprotectedCommand), typeof(Unit)),
            ]));

        ex.Message.ShouldContain("does not implement");
        ex.Message.ShouldContain(nameof(IAuthorizedRequest));
    }

    private sealed record ProtectedCommand : ICommand<Unit>, IAuthorizedRequest
    {
        public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
    }

    [Fact]
    public void Registering_the_same_name_twice_fails_at_construction()
    {
        // Duplicate names would make dispatch depend on registration order, which is exactly
        // the kind of thing nobody notices until the wrong handler runs.
        InvalidOperationException ex = Should.Throw<InvalidOperationException>(() =>
            new IpcCommandRegistry(
            [
                new IpcCommandDescriptor("Test.Duplicate", typeof(ProtectedCommand), typeof(Unit)),
                new IpcCommandDescriptor("Test.Duplicate", typeof(ProtectedCommand), typeof(Unit)),
            ]));

        ex.Message.ShouldContain("more than once");
    }

    [Fact]
    public void Read_commands_require_only_the_view_permission()
    {
        // A query that demanded a write permission would push operators toward running the
        // console with more privilege than they need.
        IpcCommandRegistry registry = new();

        registry.TryResolve("Domains.List", out IpcCommandDescriptor? list).ShouldBeTrue();

        IAuthorizedRequest instance =
            (IAuthorizedRequest)Activator.CreateInstance(list!.RequestType)!;

        instance.RequiredPermission.ShouldBe(AdminPermission.ViewServerState);
    }

    [Fact]
    public void Write_commands_require_the_manage_permission()
    {
        IpcCommandRegistry registry = new();

        registry.TryResolve("Domains.Delete", out IpcCommandDescriptor? delete).ShouldBeTrue();

        IAuthorizedRequest instance =
            (IAuthorizedRequest)Activator.CreateInstance(delete!.RequestType)!;

        instance.RequiredPermission.ShouldBe(AdminPermission.ManageDomains);
    }
}
