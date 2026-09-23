using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MailServer.Application.Common;
using MailServer.Application.Domains.Commands;
using MailServer.Application.Domains.Dtos;
using MailServer.Application.Domains.Queries;
using MailServer.Domain.Entities;
using MailServer.Ipc.Client;
using Microsoft.Extensions.Logging;

namespace MailServer.Admin.ViewModels;

/// <summary>
/// The domains grid: list, create, enable, disable and delete hosted mail domains.
/// </summary>
/// <remarks>
/// Every operation goes through <see cref="IAdminGateway"/> to the service. This view model
/// cannot open a database connection even if it tried: <c>MailServer.Admin</c> does not
/// reference any persistence project, so no database driver exists in its dependency closure.
/// </remarks>
public sealed partial class DomainsViewModel(
    IAdminGateway gateway,
    ILogger<DomainsViewModel> logger) : PageViewModel(logger)
{
    public override string Title => "Domains";

    public ObservableCollection<DomainSummaryDto> Domains { get; } = [];

    [ObservableProperty]
    public partial DomainSummaryDto? SelectedDomain { get; set; }

    [ObservableProperty]
    public partial string? SearchText { get; set; }

    [ObservableProperty]
    public partial long? TotalCount { get; set; }

    [ObservableProperty]
    public partial int Page { get; set; }

    [ObservableProperty]
    public partial bool HasMorePages { get; set; }

    // ---- New-domain form ---------------------------------------------------------------
    // Held here rather than in a dialog code-behind, so the form is testable without a UI.

    [ObservableProperty]
    public partial string NewDomainName { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string NewDomainMailHostname { get; set; } = string.Empty;

    [ObservableProperty]
    public partial int NewDomainQuotaGigabytes { get; set; } = 5;

    /// <summary>
    /// Typed to confirm a permanent deletion.
    /// </summary>
    /// <remarks>
    /// Requiring the administrator to type the domain name matches how Windows Server tooling
    /// guards destructive operations, and makes an accidental click on the wrong row
    /// essentially impossible.
    /// </remarks>
    [ObservableProperty]
    public partial string DeleteConfirmationText { get; set; } = string.Empty;

    /// <summary>The mail hostname being typed for the selected domain.</summary>
    /// <remarks>
    /// A domain cannot be enabled without one, and the create form leaves it optional, so this
    /// is how a domain created without one gets it. Filled from the selection and saved only
    /// when it differs.
    /// </remarks>
    [ObservableProperty]
    public partial string EditMailHostname { get; set; } = string.Empty;

    public bool CanSetMailHostname =>
        SelectedDomain is not null &&
        !string.IsNullOrWhiteSpace(EditMailHostname) &&
        !string.Equals(EditMailHostname.Trim(), SelectedDomain.MailHostname, StringComparison.OrdinalIgnoreCase);

    public bool CanDeletePermanently =>
        SelectedDomain is not null &&
        string.Equals(DeleteConfirmationText.Trim(), SelectedDomain.Name, StringComparison.OrdinalIgnoreCase);

    protected override async Task OnLoadAsync()
    {
        GetDomainsQuery query = new()
        {
            NameContains = string.IsNullOrWhiteSpace(SearchText) ? null : SearchText.Trim(),
            Page = Page,
            PageSize = PagedRequest.DefaultPageSize,
            SortBy = DomainSortField.Name,
        };

        PagedResult<DomainSummaryDto> result = await gateway
            .GetDomainsAsync(query)
            .ConfigureAwait(true);

        Guid? previouslySelected = SelectedDomain?.Id;

        Domains.Clear();
        foreach (DomainSummaryDto domain in result.Items)
        {
            Domains.Add(domain);
        }

        TotalCount = result.TotalCount;
        HasMorePages = result.HasMore;

        // Re-select the same row after a refresh. Losing the selection every few seconds
        // makes a self-refreshing grid unusable.
        SelectedDomain = previouslySelected is null
            ? null
            : Domains.FirstOrDefault(d => d.Id == previouslySelected.Value);
    }

    [RelayCommand]
    private Task RefreshAsync() => LoadAsync();

    [RelayCommand]
    private Task SearchAsync()
    {
        Page = 0;
        return LoadAsync();
    }

    [RelayCommand]
    private Task NextPageAsync()
    {
        if (!HasMorePages)
        {
            return Task.CompletedTask;
        }

        Page++;
        return LoadAsync();
    }

    [RelayCommand]
    private Task PreviousPageAsync()
    {
        if (Page == 0)
        {
            return Task.CompletedTask;
        }

        Page--;
        return LoadAsync();
    }

    [RelayCommand]
    private Task CreateDomainAsync() => ExecuteAsync(async () =>
    {
        CreateDomainCommand command = new()
        {
            Name = NewDomainName.Trim(),
            MailHostname = string.IsNullOrWhiteSpace(NewDomainMailHostname)
                ? null
                : NewDomainMailHostname.Trim(),
            DefaultMailboxQuotaBytes = NewDomainQuotaGigabytes <= 0
                ? 0
                : NewDomainQuotaGigabytes * 1024L * 1024 * 1024,
            MaxMessageSizeBytes = MailDomain.DefaultMaxMessageSizeBytes,
        };

        // No client-side name validation. The server validates, and a second implementation
        // here would eventually disagree with it - showing the user a rule the server does
        // not actually enforce, or refusing input the server would have accepted.
        await gateway.CreateDomainAsync(command).ConfigureAwait(true);

        NewDomainName = string.Empty;
        NewDomainMailHostname = string.Empty;
    });

    [RelayCommand]
    private Task SetMailHostnameAsync() => ExecuteAsync(async () =>
    {
        if (SelectedDomain is null)
        {
            return;
        }

        // Through the gateway's setter rather than UpdateDomainAsync, which replaces every
        // setting and would reset the domain's quotas and catch-all to their defaults.
        await gateway.SetDomainMailHostnameAsync(SelectedDomain.Id, EditMailHostname).ConfigureAwait(true);
    });

    [RelayCommand]
    private Task EnableDomainAsync() => ExecuteAsync(async () =>
    {
        if (SelectedDomain is null)
        {
            return;
        }

        await gateway.SetDomainStatusAsync(SelectedDomain.Id, enabled: true).ConfigureAwait(true);
    });

    [RelayCommand]
    private Task DisableDomainAsync() => ExecuteAsync(async () =>
    {
        if (SelectedDomain is null)
        {
            return;
        }

        await gateway.SetDomainStatusAsync(SelectedDomain.Id, enabled: false).ConfigureAwait(true);
    });

    [RelayCommand]
    private Task MarkForDeletionAsync() => ExecuteAsync(async () =>
    {
        if (SelectedDomain is null)
        {
            return;
        }

        await gateway
            .DeleteDomainAsync(SelectedDomain.Id, permanently: false)
            .ConfigureAwait(true);
    });

    [RelayCommand]
    private Task DeletePermanentlyAsync() => ExecuteAsync(async () =>
    {
        if (SelectedDomain is null || !CanDeletePermanently)
        {
            return;
        }

        await gateway
            .DeleteDomainAsync(SelectedDomain.Id, permanently: true)
            .ConfigureAwait(true);

        DeleteConfirmationText = string.Empty;
        SelectedDomain = null;
    });

    partial void OnSelectedDomainChanged(DomainSummaryDto? value)
    {
        // Clear the typed confirmation whenever the selection moves, so a phrase typed for
        // one domain can never authorise deleting another.
        DeleteConfirmationText = string.Empty;
        OnPropertyChanged(nameof(CanDeletePermanently));

        EditMailHostname = value?.MailHostname ?? string.Empty;
        OnPropertyChanged(nameof(CanSetMailHostname));
    }

    partial void OnEditMailHostnameChanged(string value) =>
        OnPropertyChanged(nameof(CanSetMailHostname));

    partial void OnDeleteConfirmationTextChanged(string value) =>
        OnPropertyChanged(nameof(CanDeletePermanently));
}
