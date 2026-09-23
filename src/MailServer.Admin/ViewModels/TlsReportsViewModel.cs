using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MailServer.Application.Deliverability.Dtos;
using MailServer.Application.Domains.Dtos;
using MailServer.Ipc.Client;
using Microsoft.Extensions.Logging;

namespace MailServer.Admin.ViewModels;

/// <summary>
/// The TLS reports other senders have delivered about this server's domains, and a place to
/// read one that arrived some other way.
/// </summary>
/// <remarks>
/// <para>
/// <b>The only page that shows a real handshake from a real sender.</b> A certificate that
/// validates on this host and fails at Google is invisible to the readiness report and is
/// exactly what these say. The report is about configuration; this page is about what happened.
/// That difference is why this is a page of its own rather than a section of the readiness
/// report, which checks that TLS-RPT is <i>published</i> and never reads what arrives.
/// </para>
/// <para>
/// <b>Every figure is a claim.</b> A report is unauthenticated — anyone who can reach the
/// <c>rua</c> address can send one — so the page says whose claim each row is and leaves the
/// judgement to several independent senders agreeing.
/// </para>
/// <para>
/// <b>Hosted domains only, picked rather than typed.</b> The service files a report under the
/// domain whose mailbox received it, so there is nothing to list for a domain this server does
/// not host. The pasted-report analyser has no such limit: it reads whatever it is given.
/// </para>
/// </remarks>
public sealed partial class TlsReportsViewModel(
    IAdminGateway gateway,
    ILogger<TlsReportsViewModel> logger) : PageViewModel(logger)
{
    public override string Title => "TLS Reports";

    public ObservableCollection<DomainSummaryDto> Domains { get; } = [];

    [ObservableProperty]
    public partial DomainSummaryDto? SelectedDomain { get; set; }

    /// <summary>The selected domain's collected reports, newest first.</summary>
    public ObservableCollection<CollectedTlsReportDto> Reports { get; } = [];

    [ObservableProperty]
    public partial CollectedTlsReportDto? SelectedReport { get; set; }

    /// <summary>
    /// Whether the selected domain has nothing collected, which the page explains rather than
    /// leaving as an empty grid.
    /// </summary>
    /// <remarks>
    /// An empty list usually means collection is off, which it is by default, or the
    /// <c>_smtp._tls</c> record is not published — not that every sender is happy. Saying so
    /// keeps an operator from reading silence as a clean bill of health.
    /// </remarks>
    public bool HasNoReports => SelectedDomain is not null && Reports.Count == 0;

    // ---- A report supplied by hand ----------------------------------------------------------

    /// <summary>The report's JSON, as pasted.</summary>
    [ObservableProperty]
    public partial string PastedReport { get; set; } = string.Empty;

    [ObservableProperty]
    public partial TlsReportDto? Analysis { get; set; }

    public bool HasAnalysis => Analysis is not null;

    public bool CanAnalyse => !string.IsNullOrWhiteSpace(PastedReport);

    protected override async Task OnLoadAsync()
    {
        Application.Common.PagedResult<DomainSummaryDto> domains = await gateway
            .GetDomainsAsync(new Application.Domains.Queries.GetDomainsQuery())
            .ConfigureAwait(true);

        Guid? previous = SelectedDomain?.Id;

        Domains.Clear();

        foreach (DomainSummaryDto domain in domains.Items)
        {
            Domains.Add(domain);
        }

        // Setting the selection while this load holds the busy flag does not fetch - the change
        // handler's command sees the flag and stands down - so the fetch happens here, once.
        SelectedDomain = Domains.FirstOrDefault(d => d.Id == previous) ?? Domains.FirstOrDefault();

        await LoadReportsAsync().ConfigureAwait(true);
    }

    partial void OnSelectedDomainChanged(DomainSummaryDto? value) =>
        _ = ExecuteAsync(LoadReportsAsync, reloadAfter: false);

    partial void OnPastedReportChanged(string value) => OnPropertyChanged(nameof(CanAnalyse));

    [RelayCommand]
    private Task RefreshAsync() => LoadAsync();

    [RelayCommand]
    private Task AnalyseAsync() => ExecuteAsync(
        async () =>
        {
            Analysis = await gateway.AnalyseTlsReportAsync(PastedReport).ConfigureAwait(true);

            OnPropertyChanged(nameof(HasAnalysis));
        },
        reloadAfter: false);

    private async Task LoadReportsAsync()
    {
        Guid? previous = SelectedReport?.Id;

        Reports.Clear();

        if (SelectedDomain is { } domain)
        {
            foreach (CollectedTlsReportDto report in await gateway
                         .GetCollectedTlsReportsAsync(domain.Name)
                         .ConfigureAwait(true))
            {
                Reports.Add(report);
            }
        }

        SelectedReport = Reports.FirstOrDefault(r => r.Id == previous) ?? Reports.FirstOrDefault();

        OnPropertyChanged(nameof(HasNoReports));
    }
}
