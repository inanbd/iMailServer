using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Domains.Commands;
using MailServer.Application.Domains.Dtos;
using MailServer.Application.Domains.Validators;
using MailServer.Application.Tests.Fakes;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.Logging.Abstractions;

namespace MailServer.Application.Tests.Domains;

public sealed class CreateDomainCommandHandlerTests
{
    private readonly FakeDomainRepository _domains = new();
    private readonly FakeClock _clock = new();

    private CreateDomainCommandHandler CreateHandler() =>
        new(_domains, _clock, NullLogger<CreateDomainCommandHandler>.Instance);

    [Fact]
    public async Task A_domain_is_created_in_pending_state()
    {
        CreateDomainCommandHandler handler = CreateHandler();

        DomainSummaryDto result = await handler.Handle(
            new CreateDomainCommand { Name = "example.com" },
            CancellationToken.None);

        result.Name.ShouldBe("example.com");
        result.Status.ShouldBe(DomainStatus.Pending);
        result.MailboxCount.ShouldBe(0);

        _domains.All.ShouldHaveSingleItem().Name.Value.ShouldBe("example.com");
    }

    [Fact]
    public async Task A_unicode_domain_name_is_normalised_to_punycode_on_the_way_in()
    {
        CreateDomainCommandHandler handler = CreateHandler();

        DomainSummaryDto result = await handler.Handle(
            new CreateDomainCommand { Name = "bücher.example" },
            CancellationToken.None);

        result.Name.ShouldBe("xn--bcher-kva.example");
        result.DisplayName.ShouldBe("bücher.example");
    }

    [Fact]
    public async Task Creating_a_domain_that_already_exists_is_rejected()
    {
        _domains.Seed(MailDomain.Create(DomainId.New(), DomainName.Parse("example.com"), _clock.UtcNow));

        CreateDomainCommandHandler handler = CreateHandler();

        DuplicateEntityException ex = await Should.ThrowAsync<DuplicateEntityException>(
            () => handler.Handle(new CreateDomainCommand { Name = "example.com" }, CancellationToken.None));

        ex.Identifier.ShouldBe("example.com");
    }

    [Fact]
    public async Task Duplicate_detection_is_case_insensitive()
    {
        _domains.Seed(MailDomain.Create(DomainId.New(), DomainName.Parse("example.com"), _clock.UtcNow));

        CreateDomainCommandHandler handler = CreateHandler();

        await Should.ThrowAsync<DuplicateEntityException>(
            () => handler.Handle(new CreateDomainCommand { Name = "EXAMPLE.COM" }, CancellationToken.None));
    }

    [Fact]
    public void The_command_declares_the_permission_it_requires() =>
        new CreateDomainCommand { Name = "example.com" }
            .RequiredPermission.ShouldBe(AdminPermission.ManageDomains);

    [Fact]
    public void The_command_describes_itself_for_audit_without_exposing_anything_sensitive()
    {
        AuditDescriptor descriptor = new CreateDomainCommand
        {
            Name = "example.com",
            MailHostname = "mail.example.com",
        }.DescribeForAudit();

        descriptor.Action.ShouldBe("Domain.Create");
        descriptor.TargetType.ShouldBe(nameof(MailDomain));
        descriptor.TargetIdentifier.ShouldBe("example.com");
    }

    [Fact]
    public void The_command_is_transactional_and_auditable_and_authorized()
    {
        // These marker interfaces are what drive the pipeline. A command missing one loses
        // the corresponding protection silently, so the contract is asserted directly.
        CreateDomainCommand command = new() { Name = "example.com" };

        command.ShouldBeAssignableTo<ITransactionalRequest>();
        command.ShouldBeAssignableTo<IAuditableRequest>();
        command.ShouldBeAssignableTo<IAuthorizedRequest>();
    }
}

public sealed class DeleteDomainCommandHandlerTests
{
    private readonly FakeDomainRepository _domains = new();
    private readonly FakeClock _clock = new();

    private DeleteDomainCommandHandler CreateHandler() =>
        new(_domains, _clock, NullLogger<DeleteDomainCommandHandler>.Instance);

    private MailDomain SeedDomain()
    {
        MailDomain domain = MailDomain.Create(
            DomainId.New(),
            DomainName.Parse("example.com"),
            _clock.UtcNow);

        _domains.Seed(domain);
        return domain;
    }

    [Fact]
    public async Task The_default_delete_only_marks_the_domain_for_deletion()
    {
        MailDomain domain = SeedDomain();

        await CreateHandler().Handle(
            new DeleteDomainCommand { DomainId = domain.Id.Value },
            CancellationToken.None);

        // Deferred deletion lets queued mail drain and makes an accidental deletion
        // recoverable inside the retention window.
        _domains.All.ShouldHaveSingleItem().Status.ShouldBe(DomainStatus.PendingDeletion);
    }

    [Fact]
    public async Task Permanent_deletion_is_refused_while_mailboxes_remain()
    {
        MailDomain domain = SeedDomain();
        _domains.MailboxCountToReport = 3;

        DomainRuleViolationException ex = await Should.ThrowAsync<DomainRuleViolationException>(
            () => CreateHandler().Handle(
                new DeleteDomainCommand { DomainId = domain.Id.Value, PermanentlyDelete = true },
                CancellationToken.None));

        // Removing the domain first would orphan every .eml file belonging to those
        // mailboxes: the rows would be gone, the files would not, and nothing would ever
        // reclaim them.
        ex.Code.ShouldBe("domain.delete.has_mailboxes");
        _domains.All.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task Permanent_deletion_succeeds_once_no_mailboxes_remain()
    {
        MailDomain domain = SeedDomain();
        _domains.MailboxCountToReport = 0;

        await CreateHandler().Handle(
            new DeleteDomainCommand { DomainId = domain.Id.Value, PermanentlyDelete = true },
            CancellationToken.None);

        _domains.All.ShouldBeEmpty();
    }

    [Fact]
    public async Task Deleting_a_domain_that_does_not_exist_reports_not_found() =>
        await Should.ThrowAsync<EntityNotFoundException>(
            () => CreateHandler().Handle(
                new DeleteDomainCommand { DomainId = Guid.NewGuid() },
                CancellationToken.None));

    [Fact]
    public void The_audit_action_distinguishes_marking_from_deleting()
    {
        new DeleteDomainCommand { DomainId = Guid.NewGuid() }
            .DescribeForAudit().Action.ShouldBe("Domain.MarkForDeletion");

        new DeleteDomainCommand { DomainId = Guid.NewGuid(), PermanentlyDelete = true }
            .DescribeForAudit().Action.ShouldBe("Domain.Delete");
    }
}

public sealed class SetDomainStatusCommandHandlerTests
{
    private readonly FakeDomainRepository _domains = new();
    private readonly FakeClock _clock = new();

    private SetDomainStatusCommandHandler CreateHandler() =>
        new(_domains, _clock, NullLogger<SetDomainStatusCommandHandler>.Instance);

    [Fact]
    public async Task Enabling_a_domain_without_a_mail_hostname_is_rejected_by_the_aggregate()
    {
        MailDomain domain = MailDomain.Create(
            DomainId.New(),
            DomainName.Parse("example.com"),
            _clock.UtcNow);

        _domains.Seed(domain);

        // The handler does not re-implement this rule. The aggregate owns it, and a rule
        // implemented in two places eventually disagrees with itself.
        DomainRuleViolationException ex = await Should.ThrowAsync<DomainRuleViolationException>(
            () => CreateHandler().Handle(
                new SetDomainStatusCommand { DomainId = domain.Id.Value, Enabled = true },
                CancellationToken.None));

        ex.Code.ShouldBe("domain.enable.no_hostname");
    }

    [Fact]
    public async Task Enabling_a_domain_with_a_mail_hostname_succeeds()
    {
        MailDomain domain = MailDomain.Create(
            DomainId.New(),
            DomainName.Parse("example.com"),
            _clock.UtcNow,
            DomainName.Parse("mail.example.com"));

        _domains.Seed(domain);

        await CreateHandler().Handle(
            new SetDomainStatusCommand { DomainId = domain.Id.Value, Enabled = true },
            CancellationToken.None);

        _domains.All.ShouldHaveSingleItem().Status.ShouldBe(DomainStatus.Active);
    }
}

public sealed class DomainValidatorTests
{
    [Theory]
    [InlineData("example.com", true)]
    [InlineData("mail.example.co.uk", true)]
    [InlineData("bücher.example", true)]
    [InlineData("", false)]
    [InlineData("localhost", false)]
    [InlineData("-bad.example.com", false)]
    [InlineData("example..com", false)]
    public void Create_validates_the_domain_name(string name, bool expectedValid)
    {
        CreateDomainCommandValidator validator = new();

        validator.Validate(new CreateDomainCommand { Name = name }).IsValid.ShouldBe(expectedValid);
    }

    [Fact]
    public void Create_rejects_a_negative_quota()
    {
        CreateDomainCommandValidator validator = new();

        validator.Validate(new CreateDomainCommand
        {
            Name = "example.com",
            DefaultMailboxQuotaBytes = -1,
        }).IsValid.ShouldBeFalse();
    }

    [Fact]
    public void Create_accepts_a_zero_quota_meaning_unlimited()
    {
        CreateDomainCommandValidator validator = new();

        validator.Validate(new CreateDomainCommand
        {
            Name = "example.com",
            DefaultMailboxQuotaBytes = 0,
        }).IsValid.ShouldBeTrue();
    }

    [Fact]
    public void Create_rejects_a_max_message_size_below_the_floor()
    {
        CreateDomainCommandValidator validator = new();

        validator.Validate(new CreateDomainCommand
        {
            Name = "example.com",
            MaxMessageSizeBytes = 1024,
        }).IsValid.ShouldBeFalse();
    }

    [Fact]
    public void Update_requires_a_catch_all_destination_when_the_policy_selects_one()
    {
        UpdateDomainCommandValidator validator = new();

        validator.Validate(new UpdateDomainCommand
        {
            DomainId = Guid.NewGuid(),
            CatchAllPolicy = CatchAllPolicy.DeliverToCatchAll,
            CatchAllMailbox = null,
        }).IsValid.ShouldBeFalse();

        validator.Validate(new UpdateDomainCommand
        {
            DomainId = Guid.NewGuid(),
            CatchAllPolicy = CatchAllPolicy.DeliverToCatchAll,
            CatchAllMailbox = "catchall@example.com",
        }).IsValid.ShouldBeTrue();
    }

    [Fact]
    public void A_page_size_beyond_the_maximum_is_rejected()
    {
        // Unbounded paging is a denial-of-service vector against the server's own database.
        GetDomainsQueryValidator validator = new();

        validator.Validate(new Application.Domains.Queries.GetDomainsQuery
        {
            PageSize = 10_000,
        }).IsValid.ShouldBeFalse();
    }

    [Fact]
    public void An_out_of_range_sort_column_is_rejected()
    {
        // The sort column is a closed enum precisely because identifiers cannot be
        // parameterised. This closes the remaining gap of an integer cast onto the enum.
        GetDomainsQueryValidator validator = new();

        validator.Validate(new Application.Domains.Queries.GetDomainsQuery
        {
            SortBy = (DomainSortField)999,
        }).IsValid.ShouldBeFalse();
    }
}
