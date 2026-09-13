using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MailServer.Application.Security.Dtos;
using MailServer.Ipc.Client;
using Microsoft.Extensions.Logging;

namespace MailServer.Admin.ViewModels;

/// <summary>The security overview: posture, active sessions, and password change.</summary>
public sealed partial class SecurityViewModel(
    IAdminGateway gateway,
    ILogger<SecurityViewModel> logger) : PageViewModel(logger)
{
    public override string Title => "Security";

    [ObservableProperty]
    public partial SecurityStatusDto? Status { get; set; }

    public ObservableCollection<AdminSessionDto> Sessions { get; } = [];

    [ObservableProperty]
    public partial AdminSessionDto? SelectedSession { get; set; }

    [ObservableProperty]
    public partial string? PasswordChangeMessage { get; set; }

    /// <summary>
    /// True when secrets are protected by the development scheme.
    /// </summary>
    /// <remarks>
    /// Surfaced prominently rather than buried in a status line: an installation running the
    /// file-backed protector in anger is a serious misconfiguration, and the whole point of the
    /// scheme reporting itself as non-production is that somebody sees it.
    /// </remarks>
    public bool HasSecretProtectionWarning =>
        Status is { SecretProtectionIsProductionGrade: false };

    /// <summary>True when no recovery key is available, which leaves no route back in.</summary>
    public bool HasNoRecoveryKey => Status is { HasRecoveryKey: false };

    /// <summary>True when sign-in failures in the last day suggest a guessing campaign.</summary>
    public bool HasRecentFailures => Status is { FailedAttemptsInLastDay: > 0 };

    protected override async Task OnLoadAsync()
    {
        Status = await gateway.GetSecurityStatusAsync().ConfigureAwait(true);

        IReadOnlyList<AdminSessionDto> sessions =
            await gateway.GetActiveSessionsAsync().ConfigureAwait(true);

        Guid? previouslySelected = SelectedSession?.Id;

        Sessions.Clear();
        foreach (AdminSessionDto session in sessions)
        {
            Sessions.Add(session);
        }

        SelectedSession = previouslySelected is null
            ? null
            : Sessions.FirstOrDefault(s => s.Id == previouslySelected.Value);

        OnPropertyChanged(nameof(HasSecretProtectionWarning));
        OnPropertyChanged(nameof(HasNoRecoveryKey));
        OnPropertyChanged(nameof(HasRecentFailures));
    }

    [RelayCommand]
    private Task RefreshAsync() => LoadAsync();

    /// <summary>
    /// Changes the master password.
    /// </summary>
    /// <remarks>
    /// Passwords arrive as arguments rather than bound properties, for the same reason as in
    /// <see cref="AuthenticationViewModel"/>: a bound string would sit in the binding engine for
    /// the lifetime of the view.
    /// </remarks>
    public Task ChangePasswordAsync(
        string currentPassword,
        string newPassword,
        string confirmPassword,
        bool keepOtherSessions) =>
        ExecuteAsync(async () =>
        {
            await gateway
                .ChangeMasterPasswordAsync(
                    currentPassword,
                    newPassword,
                    confirmPassword,
                    keepOtherSessions)
                .ConfigureAwait(true);

            PasswordChangeMessage = keepOtherSessions
                ? "The master password was changed. Other sessions were left active."
                : "The master password was changed and every session was revoked, including " +
                  "this one. Sign in again with the new password.";
        }, reloadAfter: keepOtherSessions);

    [RelayCommand]
    private Task RevokeSessionAsync() => ExecuteAsync(async () =>
    {
        if (SelectedSession is null || SelectedSession.IsCurrent)
        {
            // Revoking one's own session through this screen would look like a crash. Sign-out
            // is the deliberate way to end the current session.
            return;
        }

        await gateway.RevokeSessionAsync(SelectedSession.Id).ConfigureAwait(true);
    });
}

/// <summary>The audit trail viewer.</summary>
/// <remarks>
/// Read-only by construction: there is no mutating command on this view model, and no
/// UPDATE or DELETE against the audit table anywhere in the product. An audit trail an
/// administrator can edit is not an audit trail.
/// </remarks>
public sealed partial class AuditLogViewModel(
    IAdminGateway gateway,
    ILogger<AuditLogViewModel> logger) : PageViewModel(logger)
{
    public override string Title => "Audit Log";

    public ObservableCollection<AuditRecordDto> Records { get; } = [];

    [ObservableProperty]
    public partial AuditRecordDto? SelectedRecord { get; set; }

    [ObservableProperty]
    public partial string? ActionFilter { get; set; }

    [ObservableProperty]
    public partial string? CorrelationIdFilter { get; set; }

    [ObservableProperty]
    public partial int Page { get; set; }

    [ObservableProperty]
    public partial long? TotalCount { get; set; }

    [ObservableProperty]
    public partial bool HasMorePages { get; set; }

    protected override async Task OnLoadAsync()
    {
        Application.Common.PagedResult<AuditRecordDto> result = await gateway
            .GetAuditLogAsync(new Application.Security.Queries.GetAuditLogQuery
            {
                Action = string.IsNullOrWhiteSpace(ActionFilter) ? null : ActionFilter.Trim(),
                CorrelationId = string.IsNullOrWhiteSpace(CorrelationIdFilter)
                    ? null
                    : CorrelationIdFilter.Trim(),
                Page = Page,
                PageSize = Application.Common.PagedRequest.DefaultPageSize,
            })
            .ConfigureAwait(true);

        Records.Clear();
        foreach (AuditRecordDto record in result.Items)
        {
            Records.Add(record);
        }

        TotalCount = result.TotalCount;
        HasMorePages = result.HasMore;
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

    /// <summary>
    /// Pivots to every audit entry sharing the selected record's correlation id.
    /// </summary>
    /// <remarks>
    /// The single most useful thing an audit viewer can do during an incident: "show me
    /// everything that happened as part of that one operation".
    /// </remarks>
    [RelayCommand]
    private Task ShowRelatedAsync()
    {
        if (SelectedRecord is null)
        {
            return Task.CompletedTask;
        }

        CorrelationIdFilter = SelectedRecord.CorrelationId;
        ActionFilter = null;
        Page = 0;

        return LoadAsync();
    }
}

/// <summary>The security event log viewer.</summary>
public sealed partial class SecurityEventsViewModel(
    IAdminGateway gateway,
    ILogger<SecurityEventsViewModel> logger) : PageViewModel(logger)
{
    public override string Title => "Security Events";

    public ObservableCollection<SecurityEventDto> Events { get; } = [];

    [ObservableProperty]
    public partial SecurityEventDto? SelectedEvent { get; set; }

    /// <summary>
    /// Restricts the list to events flagged as warranting attention.
    /// </summary>
    /// <remarks>
    /// Defaults to true. A busy server writes a successful-sign-in event every time anyone
    /// opens the console; showing everything by default would bury the lockouts and rejected
    /// recovery keys that are the reason to look at all.
    /// </remarks>
    [ObservableProperty]
    public partial bool AlarmingOnly { get; set; } = true;

    [ObservableProperty]
    public partial int Page { get; set; }

    [ObservableProperty]
    public partial long? TotalCount { get; set; }

    [ObservableProperty]
    public partial bool HasMorePages { get; set; }

    protected override async Task OnLoadAsync()
    {
        Application.Common.PagedResult<SecurityEventDto> result = await gateway
            .GetSecurityEventsAsync(new Application.Security.Queries.GetSecurityEventsQuery
            {
                AlarmingOnly = AlarmingOnly,
                Page = Page,
                PageSize = Application.Common.PagedRequest.DefaultPageSize,
            })
            .ConfigureAwait(true);

        Events.Clear();
        foreach (SecurityEventDto securityEvent in result.Items)
        {
            Events.Add(securityEvent);
        }

        TotalCount = result.TotalCount;
        HasMorePages = result.HasMore;
    }

    [RelayCommand]
    private Task RefreshAsync() => LoadAsync();

    [RelayCommand]
    private Task ToggleAlarmingOnlyAsync()
    {
        AlarmingOnly = !AlarmingOnly;
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
}
