using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MailServer.Application.Common;
using MailServer.Application.Smtp.Dtos;
using MailServer.Application.Smtp.Queries;
using MailServer.Ipc.Client;
using Microsoft.Extensions.Logging;

namespace MailServer.Admin.ViewModels;

/// <summary>
/// The SMTP listeners and the mail that has arrived through them.
/// </summary>
/// <remarks>
/// <para>
/// <b>Read-only, and there is nothing here to make it otherwise.</b> The gateway exposes no
/// command that changes a listener, so this view model could not edit one if it wanted to.
/// Listener configuration is changed by editing the service's settings and restarting it, which
/// is the same rule as "the UI never edits the database" applied to the other kind of state.
/// </para>
/// <para>
/// <b>No message content is shown, and none is fetched.</b> What an operator needs to diagnose a
/// delivery is the envelope — who sent it, from where, to whom, and whether it landed. Reading
/// customers' mail is not an administrative function, and a screen that offered it would be
/// used.
/// </para>
/// </remarks>
public sealed partial class SmtpViewModel(
    IAdminGateway gateway,
    ILogger<SmtpViewModel> logger) : PageViewModel(logger)
{
    public override string Title => "SMTP";

    /// <summary>One row per configured listener, enabled or not.</summary>
    public ObservableCollection<SmtpListenerStatusDto> Listeners { get; } = [];

    /// <summary>A page of the received-mail log, newest first.</summary>
    public ObservableCollection<ReceivedMessageDto> Received { get; } = [];

    /// <summary>Addresses permitted to relay without authenticating.</summary>
    /// <remarks>
    /// Surfaced on the screen rather than buried in a settings file. It is the one setting that
    /// widens who may send mail through this server, and an operator should be able to see it
    /// without going looking.
    /// </remarks>
    public ObservableCollection<string> AuthorizedRelayAddresses { get; } = [];

    [ObservableProperty]
    public partial long MessagesLastDay { get; set; }

    [ObservableProperty]
    public partial long MessagesLastHour { get; set; }

    [ObservableProperty]
    public partial long StoredBytes { get; set; }

    [ObservableProperty]
    public partial bool AuthenticationAvailable { get; set; }

    [ObservableProperty]
    public partial ReceivedMessageDto? SelectedMessage { get; set; }

    /// <summary>Filters the log by sender, recipient or peer address.</summary>
    [ObservableProperty]
    public partial string SearchText { get; set; } = string.Empty;

    [ObservableProperty]
    public partial int Page { get; set; }

    [ObservableProperty]
    public partial long TotalMessages { get; set; }

    /// <summary>Rows per page. Fixed, because the service clamps it anyway.</summary>
    public int PageSize => 50;

    public bool HasPreviousPage => Page > 0;

    public bool HasNextPage => (long)(Page + 1) * PageSize < TotalMessages;

    /// <summary>
    /// True when no listener is enabled, which means this server is not accepting mail.
    /// </summary>
    /// <remarks>
    /// Given a banner rather than left to be inferred from a table of "Enabled: No" rows. A mail
    /// server that accepts no mail looks identical to one nobody is writing to, and an operator
    /// should meet that fact rather than deduce it.
    /// </remarks>
    public bool IsAcceptingNoMail => Listeners.Count > 0 && Listeners.All(l => !l.Enabled);

    /// <summary>True when nobody is on the relay allow-list, which is the correct default.</summary>
    /// <remarks>
    /// A property rather than a binding on <c>AuthorizedRelayAddresses.Count</c>: WPF would have
    /// to coerce an int through a boolean converter, which fails silently and leaves the screen
    /// quietly wrong about the one setting that widens who may send mail through this server.
    /// </remarks>
    public bool HasNoAuthorizedRelayAddresses => AuthorizedRelayAddresses.Count == 0;

    /// <summary>
    /// True when submission is configured but authentication is not available.
    /// </summary>
    /// <remarks>
    /// The combination refuses every sender — correct, but confusing to meet without
    /// explanation, so the screen says so.
    /// </remarks>
    public bool HasUnusableSubmissionListener =>
        !AuthenticationAvailable &&
        Listeners.Any(l => l.Enabled && l.Role != Domain.Enums.SmtpListenerRole.InboundMta);

    protected override async Task OnLoadAsync()
    {
        SmtpStatusDto status = await gateway.GetSmtpStatusAsync().ConfigureAwait(true);

        Listeners.Clear();

        foreach (SmtpListenerStatusDto listener in status.Listeners)
        {
            Listeners.Add(listener);
        }

        AuthorizedRelayAddresses.Clear();

        foreach (string address in status.AuthorizedRelayAddresses)
        {
            AuthorizedRelayAddresses.Add(address);
        }

        MessagesLastDay = status.MessagesLastDay;
        MessagesLastHour = status.MessagesLastHour;
        StoredBytes = status.StoredBytes;
        AuthenticationAvailable = status.AuthenticationAvailable;

        OnPropertyChanged(nameof(IsAcceptingNoMail));
        OnPropertyChanged(nameof(HasUnusableSubmissionListener));
        OnPropertyChanged(nameof(HasNoAuthorizedRelayAddresses));

        await LoadReceivedAsync().ConfigureAwait(true);
    }

    private async Task LoadReceivedAsync()
    {
        PagedResult<ReceivedMessageDto> page = await gateway
            .GetReceivedMessagesAsync(new GetReceivedMessagesQuery
            {
                Page = Page,
                PageSize = PageSize,
                Search = string.IsNullOrWhiteSpace(SearchText) ? null : SearchText,
            })
            .ConfigureAwait(true);

        Received.Clear();

        foreach (ReceivedMessageDto message in page.Items)
        {
            Received.Add(message);
        }

        TotalMessages = page.TotalCount ?? page.Items.Count;

        OnPropertyChanged(nameof(HasPreviousPage));
        OnPropertyChanged(nameof(HasNextPage));
    }

    [RelayCommand]
    private Task RefreshAsync() => LoadAsync();

    [RelayCommand]
    private Task SearchAsync() => ExecuteAsync(async () =>
    {
        // Back to the first page. Staying on page four of the previous result set while showing
        // a different filter is how an operator concludes there are no matches.
        Page = 0;

        await LoadReceivedAsync().ConfigureAwait(true);
    });

    [RelayCommand]
    private Task NextPageAsync() => ExecuteAsync(async () =>
    {
        if (!HasNextPage)
        {
            return;
        }

        Page++;

        await LoadReceivedAsync().ConfigureAwait(true);
    });

    [RelayCommand]
    private Task PreviousPageAsync() => ExecuteAsync(async () =>
    {
        if (!HasPreviousPage)
        {
            return;
        }

        Page--;

        await LoadReceivedAsync().ConfigureAwait(true);
    });
}
