using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MailServer.Application.Filtering.Dtos;
using MailServer.Ipc.Client;
using Microsoft.Extensions.Logging;

namespace MailServer.Admin.ViewModels;

/// <summary>
/// The quarantine: what the filter held, why, and what to do about it.
/// </summary>
/// <remarks>
/// <para>
/// <b>The reasons are the page, not the score.</b> A number on its own cannot be argued with,
/// and the only question an operator actually has about a held message is "why?". So the
/// signals are shown in full for whichever message is selected, and the score is a column
/// rather than the headline.
/// </para>
/// <para>
/// <b>Nothing here shows message content.</b> The listing is read under
/// <c>ViewServerState</c>; the message itself needs <c>ReadMessageContent</c>, which is the
/// permission releasing asks for. A page that rendered a held message's subject would be a way
/// to read mail with the weaker of the two — see <c>FilterSignal</c>, where that rule lives.
/// </para>
/// <para>
/// <b>Releasing is the page's reason to exist.</b> A hold an operator cannot undo is a deletion
/// with extra steps, so the release button is the primary action and discarding is the
/// secondary one — the opposite of how a page built around "get rid of the spam" would order
/// them.
/// </para>
/// </remarks>
public sealed partial class QuarantineViewModel(
    IAdminGateway gateway,
    ILogger<QuarantineViewModel> logger) : PageViewModel(logger)
{
    public override string Title => "Quarantine";

    /// <summary>What is held, newest first.</summary>
    public ObservableCollection<QuarantinedMessageDto> Messages { get; } = [];

    /// <summary>The message whose reasons are shown.</summary>
    [ObservableProperty]
    public partial QuarantinedMessageDto? Selected { get; set; }

    /// <summary>
    /// Whether to list messages that have already been released or discarded.
    /// </summary>
    /// <remarks>
    /// Off by default: the page's job is the decisions still waiting to be made. The resolved
    /// rows are kept so that "did we release that, and who decided?" has an answer, which is a
    /// question asked occasionally rather than a list read daily.
    /// </remarks>
    [ObservableProperty]
    public partial bool IncludeResolved { get; set; }

    /// <summary>What the last release achieved, for the operator who asked for it.</summary>
    [ObservableProperty]
    public partial string? LastOutcome { get; set; }

    /// <summary>Whether a message is selected and still waiting to be decided about.</summary>
    public bool CanResolve => Selected is { Status: "Held" };

    /// <summary>The selected message's reasons, heaviest first.</summary>
    /// <remarks>
    /// Ordered here rather than by the service, because the order an operator wants to read
    /// them in — what decided it, first — is a presentation choice, while the stored order is
    /// the order the checks ran in and is worth keeping as the record.
    /// </remarks>
    public IReadOnlyList<FilterSignalDto> SelectedReasons =>
        Selected is null
            ? []
            : [.. Selected.Signals.Where(s => s.Score > 0).OrderByDescending(s => s.Score)];

    protected override async Task OnLoadAsync()
    {
        IReadOnlyList<QuarantinedMessageDto> held = await gateway
            .GetQuarantineAsync(IncludeResolved)
            .ConfigureAwait(true);

        Guid? selectedId = Selected?.Id;

        Messages.Clear();

        foreach (QuarantinedMessageDto message in held)
        {
            Messages.Add(message);
        }

        // The selection survives a reload where it can. An operator who has just released one
        // message and is looking at the next should not be sent back to the top of the list.
        Selected = Messages.FirstOrDefault(m => m.Id == selectedId) ?? Messages.FirstOrDefault();
    }

    partial void OnSelectedChanged(QuarantinedMessageDto? value)
    {
        OnPropertyChanged(nameof(SelectedReasons));
        OnPropertyChanged(nameof(CanResolve));
    }

    partial void OnIncludeResolvedChanged(bool value) => _ = LoadAsync();

    [RelayCommand]
    private Task ReleaseAsync() => ExecuteAsync(async () =>
    {
        if (Selected is not { } message)
        {
            return;
        }

        QuarantineReleaseDto result = await gateway
            .ReleaseQuarantinedMessageAsync(message.Id)
            .ConfigureAwait(true);

        // A release can succeed at the quarantine and still reach nobody — an alias that now
        // points at nothing, a mailbox deleted since. Reporting "released" either way would
        // leave an operator believing mail arrived that did not.
        LastOutcome = result.Diagnostic
            ?? $"Released to {result.Delivered} mailbox(es) across {result.Recipients} recipient(s).";
    });

    [RelayCommand]
    private Task DiscardAsync() => ExecuteAsync(async () =>
    {
        if (Selected is not { } message)
        {
            return;
        }

        await gateway.DiscardQuarantinedMessageAsync(message.Id).ConfigureAwait(true);

        LastOutcome = "Discarded. The message's content has been removed.";
    });
}
