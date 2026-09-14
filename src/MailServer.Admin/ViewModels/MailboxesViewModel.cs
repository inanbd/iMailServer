using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MailServer.Application.Domains.Dtos;
using MailServer.Application.Mailboxes.Commands;
using MailServer.Application.Mailboxes.Dtos;
using MailServer.Domain.Enums;
using MailServer.Ipc.Client;
using Microsoft.Extensions.Logging;

namespace MailServer.Admin.ViewModels;

/// <summary>
/// Mailboxes and aliases for a selected domain.
/// </summary>
/// <remarks>
/// <para>
/// <b>No password is held on this view model.</b> Every password travels as a method argument
/// from the view's code-behind to the gateway and is not retained — the same rule as the master
/// password, for the same reason: a bound property outlives the operation, and everything that
/// can reach it is one more place it can leak.
/// </para>
/// <para>
/// Mailboxes and aliases share a page because they share an address space. An address is either
/// one or the other, and an operator deciding which to create is making one decision, not
/// choosing between two screens.
/// </para>
/// </remarks>
public sealed partial class MailboxesViewModel(
    IAdminGateway gateway,
    ILogger<MailboxesViewModel> logger) : PageViewModel(logger)
{
    public override string Title => "Mailboxes";

    public ObservableCollection<DomainSummaryDto> Domains { get; } = [];

    public ObservableCollection<MailboxSummaryDto> Mailboxes { get; } = [];

    public ObservableCollection<AliasDto> Aliases { get; } = [];

    public ObservableCollection<MissingRoleAddressDto> MissingRoleAddresses { get; } = [];

    [ObservableProperty]
    public partial DomainSummaryDto? SelectedDomain { get; set; }

    [ObservableProperty]
    public partial MailboxSummaryDto? SelectedMailbox { get; set; }

    [ObservableProperty]
    public partial AliasDto? SelectedAlias { get; set; }

    [ObservableProperty]
    public partial MailboxDetailDto? MailboxDetail { get; set; }

    /// <summary>True when a required or expected role address is missing.</summary>
    /// <remarks>
    /// Given a banner rather than a row in a list, because <c>postmaster@</c> is required by
    /// RFC 5321 and its absence removes the channel through which delivery problems get
    /// reported — a fact an operator should meet rather than go looking for.
    /// </remarks>
    public bool HasMissingRoleAddresses => MissingRoleAddresses.Count > 0;

    // ---- New-mailbox form -------------------------------------------------------------------
    // The password is deliberately absent. See the class remarks.

    [ObservableProperty]
    public partial string NewMailboxLocalPart { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string NewMailboxDisplayName { get; set; } = string.Empty;

    [ObservableProperty]
    public partial int NewMailboxQuotaMegabytes { get; set; }

    // ---- New-alias form ---------------------------------------------------------------------

    [ObservableProperty]
    public partial string NewAliasLocalPart { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string NewAliasTargets { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string NewAliasDescription { get; set; } = string.Empty;

    /// <summary>
    /// Typed to confirm deleting a mailbox.
    /// </summary>
    /// <remarks>
    /// The full address, because deleting the wrong mailbox destroys somebody's mail and there
    /// is no undo. Requiring it typed matches how Windows Server tooling guards destructive
    /// operations.
    /// </remarks>
    [ObservableProperty]
    public partial string DeleteConfirmationText { get; set; } = string.Empty;

    public bool CanDeleteMailbox =>
        SelectedMailbox is not null &&
        string.Equals(
            DeleteConfirmationText.Trim(),
            SelectedMailbox.Address,
            StringComparison.OrdinalIgnoreCase);

    public static IReadOnlyList<MailboxStatus> Statuses { get; } =
        [MailboxStatus.Active, MailboxStatus.Suspended, MailboxStatus.Disabled];

    protected override async Task OnLoadAsync()
    {
        Application.Common.PagedResult<DomainSummaryDto> domains = await gateway
            .GetDomainsAsync(new Application.Domains.Queries.GetDomainsQuery())
            .ConfigureAwait(true);

        Guid? previousDomain = SelectedDomain?.Id;

        Domains.Clear();
        foreach (DomainSummaryDto domain in domains.Items)
        {
            Domains.Add(domain);
        }

        SelectedDomain = previousDomain is null
            ? Domains.FirstOrDefault()
            : Domains.FirstOrDefault(d => d.Id == previousDomain.Value) ?? Domains.FirstOrDefault();

        await LoadForSelectedDomainAsync().ConfigureAwait(true);
    }

    private async Task LoadForSelectedDomainAsync()
    {
        Mailboxes.Clear();
        Aliases.Clear();
        MissingRoleAddresses.Clear();

        if (SelectedDomain is null)
        {
            OnPropertyChanged(nameof(HasMissingRoleAddresses));
            return;
        }

        Guid domainId = SelectedDomain.Id;
        Guid? previousMailbox = SelectedMailbox?.Id;

        foreach (MailboxSummaryDto mailbox in
                 await gateway.GetMailboxesAsync(domainId).ConfigureAwait(true))
        {
            Mailboxes.Add(mailbox);
        }

        foreach (AliasDto alias in await gateway.GetAliasesAsync(domainId).ConfigureAwait(true))
        {
            Aliases.Add(alias);
        }

        foreach (MissingRoleAddressDto missing in
                 await gateway.GetMissingRoleAddressesAsync(domainId).ConfigureAwait(true))
        {
            MissingRoleAddresses.Add(missing);
        }

        // Re-select the same row after a refresh; losing the selection every few seconds makes
        // a self-refreshing grid unusable.
        SelectedMailbox = previousMailbox is null
            ? null
            : Mailboxes.FirstOrDefault(m => m.Id == previousMailbox.Value);

        OnPropertyChanged(nameof(HasMissingRoleAddresses));
    }

    [RelayCommand]
    private Task RefreshAsync() => LoadAsync();

    /// <summary>
    /// Creates a mailbox.
    /// </summary>
    /// <remarks>
    /// The password arrives as an argument from the view's code-behind, which reads it from the
    /// <c>PasswordBox</c> at the moment the button is pressed. <c>PasswordBox.Password</c> is
    /// not a dependency property precisely so it cannot be bound, and working around that is
    /// the mistake this signature prevents.
    /// </remarks>
    public Task CreateMailboxAsync(string? password) => ExecuteAsync(async () =>
    {
        if (SelectedDomain is null)
        {
            return;
        }

        // No client-side validation. The server validates, and a second implementation here
        // would eventually disagree with it.
        await gateway.CreateMailboxAsync(
            SelectedDomain.Id,
            NewMailboxLocalPart.Trim(),
            string.IsNullOrWhiteSpace(NewMailboxDisplayName) ? null : NewMailboxDisplayName.Trim(),
            string.IsNullOrEmpty(password) ? null : password,
            NewMailboxQuotaMegabytes <= 0 ? 0 : NewMailboxQuotaMegabytes * 1024L * 1024L)
            .ConfigureAwait(true);

        NewMailboxLocalPart = string.Empty;
        NewMailboxDisplayName = string.Empty;
    });

    /// <summary>Sets a password on the selected mailbox.</summary>
    public Task SetPasswordAsync(string password) => ExecuteAsync(async () =>
    {
        if (SelectedMailbox is null || string.IsNullOrEmpty(password))
        {
            return;
        }

        await gateway
            .SetMailboxPasswordAsync(SelectedMailbox.Id, password)
            .ConfigureAwait(true);
    });

    [RelayCommand]
    private Task SetStatusAsync(MailboxStatus status) => ExecuteAsync(async () =>
    {
        if (SelectedMailbox is null)
        {
            return;
        }

        await gateway
            .UpdateMailboxAsync(new UpdateMailboxCommand
            {
                MailboxId = SelectedMailbox.Id,
                Status = status,
            })
            .ConfigureAwait(true);
    });

    [RelayCommand]
    private Task DeleteMailboxAsync() => ExecuteAsync(async () =>
    {
        if (SelectedMailbox is null || !CanDeleteMailbox)
        {
            return;
        }

        await gateway.DeleteMailboxAsync(SelectedMailbox.Id).ConfigureAwait(true);

        DeleteConfirmationText = string.Empty;
        SelectedMailbox = null;
    });

    [RelayCommand]
    private Task CreateAliasAsync() => ExecuteAsync(async () =>
    {
        if (SelectedDomain is null)
        {
            return;
        }

        string[] targets = NewAliasTargets.Split(
            [',', ';', '\n', '\r', ' ', '\t'],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        await gateway.CreateAliasAsync(
            SelectedDomain.Id,
            NewAliasLocalPart.Trim(),
            targets,
            string.IsNullOrWhiteSpace(NewAliasDescription) ? null : NewAliasDescription.Trim())
            .ConfigureAwait(true);

        NewAliasLocalPart = string.Empty;
        NewAliasTargets = string.Empty;
        NewAliasDescription = string.Empty;
    });

    [RelayCommand]
    private Task DeleteAliasAsync() => ExecuteAsync(async () =>
    {
        if (SelectedAlias is null)
        {
            return;
        }

        await gateway.DeleteAliasAsync(SelectedAlias.Id).ConfigureAwait(true);

        SelectedAlias = null;
    });

    partial void OnSelectedDomainChanged(DomainSummaryDto? value) => _ = LoadForSelectedDomainAsync();

    partial void OnSelectedMailboxChanged(MailboxSummaryDto? value)
    {
        // Cleared on every selection change, so a confirmation typed for one mailbox can never
        // authorise deleting a different one.
        DeleteConfirmationText = string.Empty;

        OnPropertyChanged(nameof(CanDeleteMailbox));

        MailboxDetail = null;

        if (value is not null)
        {
            _ = LoadDetailAsync(value.Id);
        }
    }

    private async Task LoadDetailAsync(Guid mailboxId)
    {
        try
        {
            MailboxDetail = await gateway.GetMailboxAsync(mailboxId).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            // Selecting a row must not be able to throw into the UI. The grid stays usable and
            // the detail pane simply stays empty.
            logger.LogWarning(
                ex,
                "The detail for mailbox {MailboxId} could not be loaded.",
                mailboxId);
        }
    }

    partial void OnDeleteConfirmationTextChanged(string value) =>
        OnPropertyChanged(nameof(CanDeleteMailbox));
}
