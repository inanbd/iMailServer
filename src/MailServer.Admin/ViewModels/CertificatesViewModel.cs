using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MailServer.Application.Certificates.Dtos;
using MailServer.Domain.Enums;
using MailServer.Domain.Policies;
using MailServer.Ipc.Client;
using Microsoft.Extensions.Logging;

namespace MailServer.Admin.ViewModels;

/// <summary>
/// The certificates page: what is installed, what it covers, and when it expires.
/// </summary>
/// <remarks>
/// <para>
/// Like every page here, it reaches the server only through <see cref="IAdminGateway"/>.
/// <c>MailServer.Admin</c> references no persistence project, so this view model could not open
/// a database connection even if someone tried to make it — there is no driver in its
/// dependency closure.
/// </para>
/// <para>
/// <b>No private key, passphrase or file path reaches this view model.</b> The DTOs carry
/// metadata only, which is what makes it safe for the grid to be copyable, for errors to be
/// logged, and for a support bundle to include a screenshot.
/// </para>
/// </remarks>
public sealed partial class CertificatesViewModel(
    IAdminGateway gateway,
    ILogger<CertificatesViewModel> logger) : PageViewModel(logger)
{
    public override string Title => "Certificates";

    public ObservableCollection<CertificateDto> Certificates { get; } = [];

    public ObservableCollection<AvailableStoreCertificateDto> StoreCertificates { get; } = [];

    [ObservableProperty]
    public partial CertificateDto? SelectedCertificate { get; set; }

    [ObservableProperty]
    public partial CertificateHealthDto? Health { get; set; }

    /// <summary>
    /// The verbatim self-signed warning, shown whenever any self-signed certificate is in use.
    /// </summary>
    /// <remarks>
    /// Read from the domain policy rather than typed into the XAML, so that the wording in the
    /// UI, the log and the documentation cannot drift apart. A warning that has three slightly
    /// different phrasings is a warning nobody quotes back accurately.
    /// </remarks>
    public static string SelfSignedWarning => CertificateRenewalPolicy.SelfSignedWarning;

    /// <summary>True when the server reports at least one self-signed certificate in use.</summary>
    public bool ShowSelfSignedWarning => Health?.SelfSignedCount > 0;

    /// <summary>
    /// True when no binding is marked as the default.
    /// </summary>
    /// <remarks>
    /// Given its own banner because the consequence is invisible until it bites: a handshake
    /// that offers no SNI hostname has nothing to be answered with, and the mail that fails is
    /// inbound mail from older MTAs, reported by the sender rather than by this server.
    /// </remarks>
    public bool ShowNoDefaultWarning => Health is { TotalCertificates: > 0, HasDefaultBinding: false };

    // ---- New self-signed certificate form ------------------------------------------------

    [ObservableProperty]
    public partial string NewCertificateHostnames { get; set; } = string.Empty;

    [ObservableProperty]
    public partial int NewCertificateKeySize { get; set; } = 3072;

    [ObservableProperty]
    public partial int NewCertificateValidityYears { get; set; } = 1;

    public static IReadOnlyList<int> KeySizes { get; } = [2048, 3072, 4096];

    public static IReadOnlyList<int> ValidityYears { get; } = [1, 2, 5];

    // ---- Binding form ---------------------------------------------------------------------

    [ObservableProperty]
    public partial string BindHostname { get; set; } = string.Empty;

    [ObservableProperty]
    public partial CertificatePurpose BindPurpose { get; set; } = CertificatePurpose.All;

    [ObservableProperty]
    public partial bool BindAsDefault { get; set; }

    /// <summary>
    /// Typed to confirm deleting a certificate.
    /// </summary>
    /// <remarks>
    /// The thumbprint rather than a friendly name, because two certificates for the same
    /// hostname during a changeover look identical in every other column — and deleting the
    /// wrong one of those is exactly the mistake this guards against.
    /// </remarks>
    [ObservableProperty]
    public partial string DeleteConfirmationText { get; set; } = string.Empty;

    public bool CanDelete =>
        SelectedCertificate is not null &&
        string.Equals(
            DeleteConfirmationText.Trim(),
            SelectedCertificate.Thumbprint,
            StringComparison.OrdinalIgnoreCase);

    protected override async Task OnLoadAsync()
    {
        IReadOnlyList<CertificateDto> certificates =
            await gateway.GetCertificatesAsync().ConfigureAwait(true);

        Guid? previouslySelected = SelectedCertificate?.Id;

        Certificates.Clear();
        foreach (CertificateDto certificate in certificates)
        {
            Certificates.Add(certificate);
        }

        SelectedCertificate = previouslySelected is null
            ? Certificates.FirstOrDefault()
            : Certificates.FirstOrDefault(c => c.Id == previouslySelected.Value);

        Health = await gateway.GetCertificateHealthAsync().ConfigureAwait(true);

        // Empty on a non-Windows host, which the server reports rather than failing, so the
        // "adopt from store" section simply has nothing to offer instead of erroring.
        IReadOnlyList<AvailableStoreCertificateDto> store =
            await gateway.GetAvailableStoreCertificatesAsync().ConfigureAwait(true);

        StoreCertificates.Clear();
        foreach (AvailableStoreCertificateDto candidate in store)
        {
            StoreCertificates.Add(candidate);
        }

        OnPropertyChanged(nameof(ShowSelfSignedWarning));
        OnPropertyChanged(nameof(ShowNoDefaultWarning));
    }

    [RelayCommand]
    private Task RefreshAsync() => LoadAsync();

    [RelayCommand]
    private Task GenerateSelfSignedAsync() => ExecuteAsync(async () =>
    {
        string[] hostnames = NewCertificateHostnames
            .Split([',', ';', '\n', '\r', ' '], StringSplitOptions.RemoveEmptyEntries |
                                                StringSplitOptions.TrimEntries);

        // No client-side hostname validation. The server validates, and a second
        // implementation here would eventually disagree with it — showing a rule the server
        // does not enforce, or refusing input it would have accepted.
        await gateway
            .GenerateSelfSignedCertificateAsync(
                hostnames,
                NewCertificateKeySize,
                NewCertificateValidityYears,
                makeDefault: Certificates.Count == 0)
            .ConfigureAwait(true);

        NewCertificateHostnames = string.Empty;
    });

    [RelayCommand]
    private Task BindAsync() => ExecuteAsync(async () =>
    {
        if (SelectedCertificate is null)
        {
            return;
        }

        await gateway
            .BindCertificateAsync(
                SelectedCertificate.Id,
                BindHostname.Trim(),
                BindPurpose,
                BindAsDefault)
            .ConfigureAwait(true);

        BindHostname = string.Empty;
        BindAsDefault = false;
    });

    [RelayCommand]
    private Task UnbindAsync(Guid bindingId) =>
        ExecuteAsync(() => gateway.UnbindCertificateAsync(bindingId));

    [RelayCommand]
    private Task SetDefaultBindingAsync(Guid bindingId) =>
        ExecuteAsync(() => gateway.SetDefaultBindingAsync(bindingId));

    [RelayCommand]
    private Task AdoptFromStoreAsync(string thumbprint) =>
        ExecuteAsync(() => gateway.AdoptStoreCertificateAsync(thumbprint, bindToHostname: null));

    [RelayCommand]
    private Task DeleteAsync() => ExecuteAsync(async () =>
    {
        if (SelectedCertificate is null || !CanDelete)
        {
            return;
        }

        await gateway.DeleteCertificateAsync(SelectedCertificate.Id).ConfigureAwait(true);

        DeleteConfirmationText = string.Empty;
        SelectedCertificate = null;
    });

    partial void OnSelectedCertificateChanged(CertificateDto? value)
    {
        // Cleared on every selection change, so a confirmation typed for one certificate can
        // never authorise deleting a different one.
        DeleteConfirmationText = string.Empty;

        OnPropertyChanged(nameof(CanDelete));
    }

    partial void OnDeleteConfirmationTextChanged(string value) =>
        OnPropertyChanged(nameof(CanDelete));
}
