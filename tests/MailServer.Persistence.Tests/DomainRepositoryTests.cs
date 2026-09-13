using MailServer.Application.Common;
using MailServer.Application.Domains.Dtos;
using MailServer.Domain.Entities;
using MailServer.Domain.Enums;
using MailServer.Domain.Exceptions;
using MailServer.Domain.ValueObjects;

namespace MailServer.Persistence.Tests;

public sealed class DomainRepositoryTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    private static MailDomain NewDomain(string name = "example.com", string? hostname = null) =>
        MailDomain.Create(
            DomainId.New(),
            DomainName.Parse(name),
            Now,
            hostname is null ? null : DomainName.Parse(hostname));

    [Fact]
    public async Task A_domain_round_trips_through_the_database_intact()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        MailDomain original = NewDomain("example.com", "mail.example.com");
        original.SetQuotas(QuotaBytes.FromGigabytes(5), QuotaBytes.FromGigabytes(500), Now);
        original.SetRequireTlsForOutbound(true, Now);

        await scope.Domains.AddAsync(original, CancellationToken.None);

        MailDomain? loaded = await scope.Domains.GetByIdAsync(original.Id, CancellationToken.None);

        loaded.ShouldNotBeNull();
        loaded.Id.ShouldBe(original.Id);
        loaded.Name.ShouldBe(original.Name);
        loaded.Status.ShouldBe(DomainStatus.Pending);
        loaded.MailHostname!.Value.ShouldBe("mail.example.com");
        loaded.DefaultMailboxQuota.Bytes.ShouldBe(5L * 1024 * 1024 * 1024);
        loaded.DomainQuota.Bytes.ShouldBe(500L * 1024 * 1024 * 1024);
        loaded.RequireTlsForOutbound.ShouldBeTrue();
        loaded.CreatedUtc.ShouldBe(original.CreatedUtc);
    }

    [Fact]
    public async Task An_international_domain_round_trips_without_corruption()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        MailDomain original = NewDomain("bücher.example");
        await scope.Domains.AddAsync(original, CancellationToken.None);

        MailDomain? loaded = await scope.Domains.GetByNameAsync(
            DomainName.Parse("bücher.example"),
            CancellationToken.None);

        loaded.ShouldNotBeNull();
        loaded.Name.Value.ShouldBe("xn--bcher-kva.example");
        loaded.Name.UnicodeValue.ShouldBe("bücher.example");
    }

    [Fact]
    public async Task Adding_a_duplicate_domain_is_rejected_by_the_unique_index()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        await scope.Domains.AddAsync(NewDomain("example.com"), CancellationToken.None);

        // This is what actually guarantees uniqueness when two administrators create the same
        // domain simultaneously and both pass the handler's pre-check. The repository maps the
        // constraint violation to the same exception type the pre-check raises.
        DuplicateEntityException ex = await Should.ThrowAsync<DuplicateEntityException>(
            () => scope.Domains.AddAsync(NewDomain("example.com"), CancellationToken.None));

        ex.Identifier.ShouldBe("example.com");
    }

    [Fact]
    public async Task Updating_a_domain_persists_the_change()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        MailDomain domain = NewDomain("example.com", "mail.example.com");
        await scope.Domains.AddAsync(domain, CancellationToken.None);

        domain.Enable(Now.AddMinutes(1));
        await scope.Domains.UpdateAsync(domain, CancellationToken.None);

        MailDomain? reloaded = await scope.Domains.GetByIdAsync(domain.Id, CancellationToken.None);

        reloaded!.Status.ShouldBe(DomainStatus.Active);
        reloaded.ModifiedUtc.ShouldBe(Now.AddMinutes(1));
    }

    [Fact]
    public async Task Updating_a_domain_that_no_longer_exists_reports_not_found()
    {
        // Silently updating zero rows is how "I saved it and it didn't save" bugs happen.
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        await Should.ThrowAsync<EntityNotFoundException>(
            () => scope.Domains.UpdateAsync(NewDomain(), CancellationToken.None));
    }

    [Fact]
    public async Task The_domain_name_is_immutable_even_through_the_repository()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        MailDomain domain = NewDomain("example.com");
        await scope.Domains.AddAsync(domain, CancellationToken.None);

        domain.SetMailHostname(DomainName.Parse("mail.example.com"), Now);
        await scope.Domains.UpdateAsync(domain, CancellationToken.None);

        MailDomain? reloaded = await scope.Domains.GetByIdAsync(domain.Id, CancellationToken.None);

        // The UPDATE statement deliberately omits Name from its SET list, so even a future
        // bug that mutated the in-memory name could not rewrite it in storage.
        reloaded!.Name.Value.ShouldBe("example.com");
    }

    [Fact]
    public async Task Only_operational_domains_are_returned_by_the_smtp_lookup()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        MailDomain active = NewDomain("active.example", "mail.active.example");
        active.Enable(Now);
        await scope.Domains.AddAsync(active, CancellationToken.None);

        await scope.Domains.AddAsync(NewDomain("pending.example"), CancellationToken.None);

        MailDomain disabled = NewDomain("disabled.example", "mail.disabled.example");
        disabled.Enable(Now);
        disabled.Disable(Now);
        await scope.Domains.AddAsync(disabled, CancellationToken.None);

        IReadOnlyList<MailDomain> operational =
            await scope.Domains.GetOperationalAsync(CancellationToken.None);

        operational.ShouldHaveSingleItem().Name.Value.ShouldBe("active.example");
    }

    [Fact]
    public async Task Removing_a_domain_deletes_it()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        MailDomain domain = NewDomain();
        await scope.Domains.AddAsync(domain, CancellationToken.None);

        await scope.Domains.RemoveAsync(domain.Id, CancellationToken.None);

        (await scope.Domains.GetByIdAsync(domain.Id, CancellationToken.None)).ShouldBeNull();
    }

    [Fact]
    public async Task Existence_checks_are_case_insensitive_via_normalisation()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        await scope.Domains.AddAsync(NewDomain("example.com"), CancellationToken.None);

        (await scope.Domains.ExistsAsync(DomainName.Parse("EXAMPLE.COM"), CancellationToken.None))
            .ShouldBeTrue();

        (await scope.Domains.ExistsAsync(DomainName.Parse("other.com"), CancellationToken.None))
            .ShouldBeFalse();
    }
}

public sealed class DomainQueriesTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 13, 12, 0, 0, TimeSpan.Zero);

    private static async Task<SqliteTestDatabase> SeedAsync(params string[] names)
    {
        SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        foreach (string name in names)
        {
            await scope.Domains.AddAsync(
                MailDomain.Create(DomainId.New(), DomainName.Parse(name), Now),
                CancellationToken.None);
        }

        return database;
    }

    [Fact]
    public async Task Search_returns_a_page_with_a_total_count()
    {
        await using SqliteTestDatabase database =
            await SeedAsync("alpha.example", "beta.example", "gamma.example");

        PagedResult<DomainSummaryDto> result = await database.CreateScope().DomainQueries
            .SearchAsync(new DomainSearchRequest { PageSize = 2 }, CancellationToken.None);

        result.Items.Count.ShouldBe(2);
        result.TotalCount.ShouldBe(3);
        result.HasMore.ShouldBeTrue();
        result.Items[0].Name.ShouldBe("alpha.example");
    }

    [Fact]
    public async Task Search_pages_without_repeating_or_dropping_rows()
    {
        await using SqliteTestDatabase database =
            await SeedAsync("a.example", "b.example", "c.example", "d.example", "e.example");

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        PagedResult<DomainSummaryDto> page0 = await scope.DomainQueries.SearchAsync(
            new DomainSearchRequest { Page = 0, PageSize = 2 }, CancellationToken.None);

        PagedResult<DomainSummaryDto> page1 = await scope.DomainQueries.SearchAsync(
            new DomainSearchRequest { Page = 1, PageSize = 2 }, CancellationToken.None);

        PagedResult<DomainSummaryDto> page2 = await scope.DomainQueries.SearchAsync(
            new DomainSearchRequest { Page = 2, PageSize = 2 }, CancellationToken.None);

        string[] seen =
        [
            .. page0.Items.Concat(page1.Items).Concat(page2.Items).Select(d => d.Name)
        ];

        // A total order in the ORDER BY is what makes this hold. Without the tie-break,
        // two pages of an unstably sorted result can show the same row twice.
        seen.Length.ShouldBe(5);
        seen.Distinct(StringComparer.Ordinal).Count().ShouldBe(5);
    }

    [Fact]
    public async Task Search_filters_by_name_substring()
    {
        await using SqliteTestDatabase database =
            await SeedAsync("alpha.example", "beta.example", "alphabet.example");

        PagedResult<DomainSummaryDto> result = await database.CreateScope().DomainQueries
            .SearchAsync(new DomainSearchRequest { NameContains = "alpha" }, CancellationToken.None);

        result.Items.Count.ShouldBe(2);
        result.Items.ShouldAllBe(d => d.Name.Contains("alpha", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_like_wildcard_in_the_search_text_is_treated_as_a_literal()
    {
        // Without escaping, searching for "a_c" would match "abc" - surprising, and a small
        // information leak about names the operator did not ask about.
        await using SqliteTestDatabase database = await SeedAsync("abc.example", "a-c.example");

        PagedResult<DomainSummaryDto> result = await database.CreateScope().DomainQueries
            .SearchAsync(new DomainSearchRequest { NameContains = "a_c" }, CancellationToken.None);

        result.Items.ShouldBeEmpty();
    }

    [Fact]
    public async Task Search_filters_by_status()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        MailDomain active = MailDomain.Create(
            DomainId.New(), DomainName.Parse("active.example"), Now, DomainName.Parse("mail.active.example"));

        active.Enable(Now);
        await scope.Domains.AddAsync(active, CancellationToken.None);

        await scope.Domains.AddAsync(
            MailDomain.Create(DomainId.New(), DomainName.Parse("pending.example"), Now),
            CancellationToken.None);

        PagedResult<DomainSummaryDto> result = await scope.DomainQueries.SearchAsync(
            new DomainSearchRequest { Statuses = [DomainStatus.Active] },
            CancellationToken.None);

        result.Items.ShouldHaveSingleItem().Name.ShouldBe("active.example");
    }

    [Fact]
    public async Task Search_can_skip_the_expensive_total_count()
    {
        await using SqliteTestDatabase database = await SeedAsync("a.example", "b.example");

        PagedResult<DomainSummaryDto> result = await database.CreateScope().DomainQueries
            .SearchAsync(
                new DomainSearchRequest { IncludeTotalCount = false },
                CancellationToken.None);

        // Counting matching rows in a multi-million-row table is often dearer than fetching
        // the page, so the caller can decline it and get "next page" instead of "page 7 of N".
        result.TotalCount.ShouldBeNull();
        result.Items.Count.ShouldBe(2);
    }

    [Fact]
    public async Task Sorting_descending_reverses_the_order()
    {
        await using SqliteTestDatabase database =
            await SeedAsync("alpha.example", "beta.example", "gamma.example");

        PagedResult<DomainSummaryDto> result = await database.CreateScope().DomainQueries
            .SearchAsync(
                new DomainSearchRequest { SortBy = DomainSortField.Name, SortDescending = true },
                CancellationToken.None);

        result.Items[0].Name.ShouldBe("gamma.example");
        result.Items[^1].Name.ShouldBe("alpha.example");
    }

    [Fact]
    public async Task Detail_returns_null_for_an_unknown_domain()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        DomainDetailDto? detail = await database.CreateScope().DomainQueries
            .GetDetailAsync(DomainId.New(), CancellationToken.None);

        detail.ShouldBeNull();
    }

    [Fact]
    public async Task Detail_reports_zero_mailboxes_for_a_new_domain()
    {
        await using SqliteTestDatabase database = new();
        await database.MigrateAsync(CancellationToken.None);

        SqliteTestDatabase.TestScope scope = database.CreateScope();

        MailDomain domain = MailDomain.Create(DomainId.New(), DomainName.Parse("example.com"), Now);
        await scope.Domains.AddAsync(domain, CancellationToken.None);

        DomainDetailDto? detail =
            await scope.DomainQueries.GetDetailAsync(domain.Id, CancellationToken.None);

        detail.ShouldNotBeNull();

        // COALESCE on the LEFT JOIN: a domain with no mailboxes must report 0, not null.
        detail.MailboxCount.ShouldBe(0);
        detail.StorageUsedBytes.ShouldBe(0);
    }
}
