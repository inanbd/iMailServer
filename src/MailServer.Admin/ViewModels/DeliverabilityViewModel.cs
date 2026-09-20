using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MailServer.Application.Deliverability.Dtos;
using MailServer.Ipc.Client;
using Microsoft.Extensions.Logging;

namespace MailServer.Admin.ViewModels;

/// <summary>
/// The deliverability page: the readiness report, the DNS plan, the header analyser and the
/// delivery test.
/// </summary>
/// <remarks>
/// <para>
/// <b>The verdict leads and the number follows.</b> <see cref="DeliverabilityReportDto"/> carries
/// both, and the order matters: the readiness verdict is the worst outcome present, while the
/// score is arithmetic over weights. A comfortable 94 beside a failing SPF check is exactly the
/// report an operator skims and then wonders why Gmail refuses their mail, so the verdict is what
/// the page leads with and the score is shown as a breakdown that can be read rather than as a
/// headline number.
/// </para>
/// <para>
/// <b>Every check shows its evidence.</b> <c>docs/Deliverability.md</c>: "A bare 94/100 that
/// cannot be explained is useless to an operator trying to fix the missing six." So the record
/// found, the value expected, the resolver used and the TTL observed all reach the grid, along
/// with the remedy — which is the only part most operators will read.
/// </para>
/// <para>
/// <b>The delivery test is the one action on this page that leaves the building.</b> It is kept
/// behind its own explicit button and its own confirmation of the destination, because unlike
/// everything else here it sends real mail from this server's IP. The service enforces that with
/// a write-level permission; this view model does not pretend to be the control.
/// </para>
/// </remarks>
public sealed partial class DeliverabilityViewModel(
    IAdminGateway gateway,
    ILogger<DeliverabilityViewModel> logger) : PageViewModel(logger)
{
    public override string Title => "Deliverability";

    // ---- The report -------------------------------------------------------------------------

    /// <summary>The domain the report and the plan are about.</summary>
    /// <remarks>
    /// Typed rather than picked from a list, because a report is worth running for a domain this
    /// server does not host yet — checking DNS before cutting mail over is exactly when it is
    /// most useful.
    /// </remarks>
    [ObservableProperty]
    public partial string Domain { get; set; } = string.Empty;

    [ObservableProperty]
    public partial DeliverabilityReportDto? Report { get; set; }

    public ObservableCollection<DeliverabilityCheckDto> Checks { get; } = [];

    public ObservableCollection<DeliverabilityCategoryDto> Categories { get; } = [];

    [ObservableProperty]
    public partial DeliverabilityCheckDto? SelectedCheck { get; set; }

    /// <summary>
    /// The checks that are not passing, which is what an operator actually came to see.
    /// </summary>
    /// <remarks>
    /// A separate collection rather than a filter toggle, so the page can show the problems
    /// first without the operator having to discover a control. The full list stays available:
    /// hiding the passes entirely would make it impossible to tell "checked and fine" from
    /// "never ran", and <c>Inconclusive</c> is a real outcome with its own meaning.
    /// </remarks>
    public ObservableCollection<DeliverabilityCheckDto> Problems { get; } = [];

    public bool HasReport => Report is not null;

    public bool HasProblems => Problems.Count > 0;

    /// <summary>True when a report ran and every check passed.</summary>
    public bool IsClean => Report is not null && Problems.Count == 0;

    // ---- The DNS plan -----------------------------------------------------------------------

    [ObservableProperty]
    public partial string? DmarcReportAddress { get; set; }

    [ObservableProperty]
    public partial string? TlsReportAddress { get; set; }

    [ObservableProperty]
    public partial DnsPlanDto? Plan { get; set; }

    public ObservableCollection<DnsRecordDto> PlannedRecords { get; } = [];

    public ObservableCollection<DnsPlanCaveatDto> PlanCaveats { get; } = [];

    /// <summary>The plan as zone-file text, for an operator who would rather paste than click.</summary>
    public string PlanZoneText => Plan?.ZoneText ?? string.Empty;

    public bool HasPlan => Plan is not null;

    // ---- The header analyser ----------------------------------------------------------------

    [ObservableProperty]
    public partial string PastedHeaders { get; set; } = string.Empty;

    [ObservableProperty]
    public partial HeaderAnalysisDto? Analysis { get; set; }

    public bool HasAnalysis => Analysis is not null;

    // ---- The delivery test ------------------------------------------------------------------

    [ObservableProperty]
    public partial string DeliveryTestFrom { get; set; } = string.Empty;

    [ObservableProperty]
    public partial string DeliveryTestTo { get; set; } = string.Empty;

    [ObservableProperty]
    public partial DeliveryTestDto? DeliveryTest { get; set; }

    public bool HasDeliveryTest => DeliveryTest is not null;

    /// <summary>
    /// Both addresses must be filled in before the button does anything.
    /// </summary>
    /// <remarks>
    /// The service validates them properly and is the authority; this only stops the obvious
    /// empty-form case, because a round trip that ends in "From is not an email address" is a
    /// round trip that sent nothing and told the operator nothing they could not see.
    /// </remarks>
    public bool CanRunDeliveryTest =>
        !string.IsNullOrWhiteSpace(DeliveryTestFrom) &&
        !string.IsNullOrWhiteSpace(DeliveryTestTo);

    protected override async Task OnLoadAsync()
    {
        // Nothing is fetched on navigation. Every action on this page makes live DNS queries, a
        // TLS handshake or an outbound connection on the operator's behalf, and doing that
        // because somebody clicked a tab would spend somebody else's resolver budget on a page
        // view. The operator names a domain and asks.
        await Task.CompletedTask.ConfigureAwait(true);
    }

    [RelayCommand]
    private Task RunReportAsync() => ExecuteAsync(
        async () =>
        {
            DeliverabilityReportDto report = await gateway
                .GetDeliverabilityReportAsync(Domain.Trim())
                .ConfigureAwait(true);

            Report = report;

            Replace(Checks, report.Checks);
            Replace(Categories, report.Categories);
            Replace(Problems, report.Checks.Where(IsProblem));

            SelectedCheck = Problems.FirstOrDefault() ?? Checks.FirstOrDefault();

            OnPropertyChanged(nameof(HasReport));
            OnPropertyChanged(nameof(HasProblems));
            OnPropertyChanged(nameof(IsClean));
        },
        reloadAfter: false);

    [RelayCommand]
    private Task BuildPlanAsync() => ExecuteAsync(
        async () =>
        {
            DnsPlanDto plan = await gateway
                .GetDnsPlanAsync(
                    Domain.Trim(),
                    Blank(DmarcReportAddress),
                    Blank(TlsReportAddress))
                .ConfigureAwait(true);

            Plan = plan;

            Replace(PlannedRecords, plan.Records);
            Replace(PlanCaveats, plan.Caveats);

            OnPropertyChanged(nameof(HasPlan));
            OnPropertyChanged(nameof(PlanZoneText));
        },
        reloadAfter: false);

    [RelayCommand]
    private Task AnalyseHeadersAsync() => ExecuteAsync(
        async () =>
        {
            Analysis = await gateway.AnalyseHeadersAsync(PastedHeaders).ConfigureAwait(true);

            OnPropertyChanged(nameof(HasAnalysis));
        },
        reloadAfter: false);

    [RelayCommand]
    private Task RunDeliveryTestAsync() => ExecuteAsync(
        async () =>
        {
            DeliveryTest = await gateway
                .RunDeliveryTestAsync(DeliveryTestFrom.Trim(), DeliveryTestTo.Trim())
                .ConfigureAwait(true);

            OnPropertyChanged(nameof(HasDeliveryTest));
        },
        reloadAfter: false);

    /// <summary>
    /// Whether a check is something the operator has to act on.
    /// </summary>
    /// <remarks>
    /// <b><c>Inconclusive</c> counts.</b> It means the check could not reach an answer — a
    /// resolver that did not respond, a certificate that could not be fetched — and treating it
    /// as a pass would report a configuration as verified that nobody verified. It is shown
    /// alongside the failures and warnings with its own outcome intact, so the difference stays
    /// visible.
    /// </remarks>
    private static bool IsProblem(DeliverabilityCheckDto check) =>
        !string.Equals(check.Outcome, "Pass", StringComparison.OrdinalIgnoreCase);

    private static string? Blank(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static void Replace<T>(ObservableCollection<T> target, IEnumerable<T> items)
    {
        target.Clear();

        foreach (T item in items)
        {
            target.Add(item);
        }
    }
}
