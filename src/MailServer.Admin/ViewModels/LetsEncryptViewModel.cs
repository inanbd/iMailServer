using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MailServer.Application.Acme.Dtos;
using MailServer.Domain.Enums;
using MailServer.Ipc.Client;
using Microsoft.Extensions.Logging;

namespace MailServer.Admin.ViewModels;

/// <summary>
/// The Let's Encrypt page: configuration, readiness, issuance and attempt history.
/// </summary>
/// <remarks>
/// <para>
/// The page is arranged around the order an operator actually works in: check what is blocking,
/// run the pre-flight, then request. Putting the request button first would invite pressing it
/// before the checks, and every premature request costs a rate-limit slot that cannot be
/// refunded.
/// </para>
/// <para>
/// No key material reaches this view model. The ACME account key never leaves the service, and
/// the DTOs carry neither it nor the name of the secret holding it.
/// </para>
/// </remarks>
public sealed partial class LetsEncryptViewModel(
    IAdminGateway gateway,
    ILogger<LetsEncryptViewModel> logger) : PageViewModel(logger)
{
    public override string Title => "Let's Encrypt";

    [ObservableProperty]
    public partial AcmeStatusDto? Status { get; set; }

    public ObservableCollection<AcmeAccountDto> Accounts { get; } = [];

    public ObservableCollection<AcmeOrderDto> Orders { get; } = [];

    public ObservableCollection<PreflightFindingDto> PreflightFindings { get; } = [];

    /// <summary>Instructions for DNS records the operator must publish by hand.</summary>
    public ObservableCollection<string> ManualDnsInstructions { get; } = [];

    [ObservableProperty]
    public partial string RequestHostnames { get; set; } = string.Empty;

    [ObservableProperty]
    public partial AcmeChallengeType? RequestChallengeType { get; set; }

    [ObservableProperty]
    public partial string? LastIssuanceMessage { get; set; }

    [ObservableProperty]
    public partial bool LastIssuanceSucceeded { get; set; }

    public static IReadOnlyList<AcmeChallengeType> ChallengeTypes { get; } =
        [AcmeChallengeType.Http01, AcmeChallengeType.Dns01];

    /// <summary>True when something must be configured before a certificate can be requested.</summary>
    public bool HasBlockingIssues => Status?.BlockingIssues.Count > 0;

    /// <summary>
    /// True when the configured directory issues certificates nothing publicly trusts.
    /// </summary>
    /// <remarks>
    /// Its own banner, because "my certificate was issued but browsers still warn" is the most
    /// common confusion with ACME and staging is almost always the answer.
    /// </remarks>
    public bool ShowStagingWarning =>
        Status is { IssuesPubliclyTrustedCertificates: false };

    public bool HasManualDnsInstructions => ManualDnsInstructions.Count > 0;

    protected override async Task OnLoadAsync()
    {
        Status = await gateway.GetAcmeStatusAsync().ConfigureAwait(true);

        IReadOnlyList<AcmeAccountDto> accounts =
            await gateway.GetAcmeAccountsAsync().ConfigureAwait(true);

        Accounts.Clear();
        foreach (AcmeAccountDto account in accounts)
        {
            Accounts.Add(account);
        }

        IReadOnlyList<AcmeOrderDto> orders =
            await gateway.GetAcmeOrdersAsync().ConfigureAwait(true);

        Orders.Clear();
        foreach (AcmeOrderDto order in orders)
        {
            Orders.Add(order);
        }

        OnPropertyChanged(nameof(HasBlockingIssues));
        OnPropertyChanged(nameof(ShowStagingWarning));
    }

    [RelayCommand]
    private Task RefreshAsync() => LoadAsync();

    /// <summary>
    /// Runs the pre-flight checks without submitting anything.
    /// </summary>
    /// <remarks>
    /// Free: it costs no rate-limit quota, which is exactly why it is offered as its own
    /// button rather than only happening inside a request.
    /// </remarks>
    [RelayCommand]
    private Task CheckReadinessAsync() => ExecuteAsync(
        async () =>
        {
            PreflightFindings.Clear();

            IReadOnlyList<PreflightFindingDto> findings = await gateway
                .CheckIssuanceReadinessAsync(SplitHostnames(), RequestChallengeType)
                .ConfigureAwait(true);

            foreach (PreflightFindingDto finding in findings)
            {
                PreflightFindings.Add(finding);
            }
        },
        reloadAfter: false);

    [RelayCommand]
    private Task RequestCertificateAsync() => ExecuteAsync(async () =>
    {
        ManualDnsInstructions.Clear();
        LastIssuanceMessage = null;

        IssuanceResultDto result = await gateway
            .RequestCertificateAsync(SplitHostnames(), RequestChallengeType)
            .ConfigureAwait(true);

        LastIssuanceSucceeded = result.Succeeded;

        LastIssuanceMessage = result.Succeeded
            ? $"Certificate issued: {result.Thumbprint}"
            : result.Failure;

        foreach (string instruction in result.ManualDnsInstructions ?? [])
        {
            ManualDnsInstructions.Add(instruction);
        }

        OnPropertyChanged(nameof(HasManualDnsInstructions));
    });

    /// <summary>
    /// Splits the hostname box on the separators an operator is likely to paste.
    /// </summary>
    /// <remarks>
    /// No validation here. The server validates, and a second implementation in the client
    /// would eventually disagree with it — refusing input the server would have accepted, or
    /// promising something it will not.
    /// </remarks>
    private string[] SplitHostnames() =>
        RequestHostnames.Split(
            [',', ';', '\n', '\r', ' ', '\t'],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
