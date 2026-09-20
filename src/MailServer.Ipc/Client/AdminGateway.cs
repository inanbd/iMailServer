using MailServer.Application.Common;
using MailServer.Application.Acme.Commands;
using MailServer.Application.Acme.Dtos;
using MailServer.Application.Acme.Queries;
using MailServer.Application.Certificates.Commands;

using MailServer.Application.Certificates.Dtos;
using MailServer.Application.Deliverability.Commands;
using MailServer.Application.Deliverability.Dtos;
using MailServer.Application.Deliverability.Queries;
using MailServer.Application.Certificates.Queries;
using MailServer.Application.Domains.Commands;
using MailServer.Application.Mailboxes.Commands;
using MailServer.Application.Mailboxes.Dtos;
using MailServer.Application.Mailboxes.Queries;
using MailServer.Application.Security.Commands;
using MailServer.Application.Security.Dtos;
using MailServer.Application.Security.Queries;
using MailServer.Application.Domains.Dtos;
using MailServer.Application.Domains.Queries;
using MailServer.Application.Smtp.Dtos;
using MailServer.Application.Smtp.Queries;
using MailServer.Application.Monitoring.Dtos;
using MailServer.Application.Monitoring.Queries;
using MailServer.Domain.Enums;
using MediatR;

namespace MailServer.Ipc.Client;

/// <summary>
/// The administration application's typed view of the service.
/// </summary>
/// <remarks>
/// <para>
/// The <b>only</b> way out of the WPF application. View models depend on this interface, so
/// they are unit-testable against a fake with no pipe, no service and no database.
/// </para>
/// <para>
/// Typed methods rather than a stringly-typed <c>Send(name, json)</c>: a mistyped command
/// name should be a compile error, not a runtime <c>UnknownCommand</c> discovered by a user.
/// </para>
/// </remarks>
public interface IAdminGateway
{
    // ---- Security ------------------------------------------------------------------------

    /// <summary>True when a session token is held locally.</summary>
    bool HasSession { get; }

    /// <summary>Asks whether setup is required. The one call permitted before signing in.</summary>
    Task<SetupStatusDto> GetSetupStatusAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Completes first-run setup and signs in.
    /// </summary>
    /// <remarks>
    /// The returned recovery key is the only time it exists in plaintext outside the
    /// administrator's head. The caller must display it before the result goes out of scope.
    /// </remarks>
    Task<SetupResultDto> CompleteSetupAsync(
        string password,
        string confirmPassword,
        CancellationToken cancellationToken = default);

    /// <summary>Signs in and adopts the resulting session.</summary>
    Task<AuthenticationResultDto> AuthenticateAsync(
        string password,
        CancellationToken cancellationToken = default);

    /// <summary>Resets the master password using the recovery key, returning a replacement key.</summary>
    Task<RecoveryKeyDto> ResetPasswordWithRecoveryKeyAsync(
        string recoveryKey,
        string newPassword,
        string confirmNewPassword,
        CancellationToken cancellationToken = default);

    /// <summary>Ends the session, locally and on the server.</summary>
    Task SignOutAsync(bool isAutoLock = false, CancellationToken cancellationToken = default);

    /// <summary>Changes the master password.</summary>
    Task ChangeMasterPasswordAsync(
        string currentPassword,
        string newPassword,
        string confirmNewPassword,
        bool keepOtherSessions = false,
        CancellationToken cancellationToken = default);

    Task<SecurityStatusDto> GetSecurityStatusAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AdminSessionDto>> GetActiveSessionsAsync(
        CancellationToken cancellationToken = default);

    Task RevokeSessionAsync(Guid sessionId, CancellationToken cancellationToken = default);

    Task<PagedResult<AuditRecordDto>> GetAuditLogAsync(
        GetAuditLogQuery query,
        CancellationToken cancellationToken = default);

    Task<PagedResult<SecurityEventDto>> GetSecurityEventsAsync(
        GetSecurityEventsQuery query,
        CancellationToken cancellationToken = default);

    // ---- SMTP --------------------------------------------------------------------------------

    /// <summary>What the SMTP subsystem is doing, and how each listener is configured.</summary>
    Task<SmtpStatusDto> GetSmtpStatusAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// A page of the received-mail log, newest first.
    /// </summary>
    /// <remarks>
    /// Envelopes only. There is no gateway method that returns message content, because there is
    /// no service command that returns it.
    /// </remarks>
    Task<PagedResult<ReceivedMessageDto>> GetReceivedMessagesAsync(
        GetReceivedMessagesQuery query,
        CancellationToken cancellationToken = default);

    // ---- Monitoring and domains ------------------------------------------------------------

    Task<DashboardDto> GetDashboardAsync(CancellationToken cancellationToken = default);

    Task<PagedResult<DomainSummaryDto>> GetDomainsAsync(
        GetDomainsQuery query,
        CancellationToken cancellationToken = default);

    Task<DomainDetailDto> GetDomainAsync(Guid domainId, CancellationToken cancellationToken = default);

    Task<DomainSummaryDto> CreateDomainAsync(
        CreateDomainCommand command,
        CancellationToken cancellationToken = default);

    Task UpdateDomainAsync(UpdateDomainCommand command, CancellationToken cancellationToken = default);

    Task SetDomainStatusAsync(Guid domainId, bool enabled, CancellationToken cancellationToken = default);

    Task DeleteDomainAsync(
        Guid domainId,
        bool permanently,
        CancellationToken cancellationToken = default);

    // ---- Certificates ---------------------------------------------------------------------
    //
    // None of these returns key material. The DTOs carry metadata and a thumbprint; private
    // keys, PFX passphrases and file paths stay in the service, which is what makes the
    // administration application safe to log from and screenshot.

    Task<IReadOnlyList<CertificateDto>> GetCertificatesAsync(
        CancellationToken cancellationToken = default);

    Task<CertificateDto> GetCertificateAsync(
        Guid certificateId,
        CancellationToken cancellationToken = default);

    Task<CertificateHealthDto> GetCertificateHealthAsync(
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AvailableStoreCertificateDto>> GetAvailableStoreCertificatesAsync(
        CancellationToken cancellationToken = default);

    Task<CertificateDto> GenerateSelfSignedCertificateAsync(
        IReadOnlyList<string> hostnames,
        int keySizeBits = 3072,
        int validityYears = 1,
        bool makeDefault = false,
        CancellationToken cancellationToken = default);

    Task<CertificateDto> ImportCertificateAsync(
        byte[] pfxBytes,
        string? passphrase,
        string? bindToHostname,
        bool makeDefault = false,
        CancellationToken cancellationToken = default);

    Task<CertificateDto> AdoptStoreCertificateAsync(
        string thumbprint,
        string? bindToHostname,
        bool makeDefault = false,
        CancellationToken cancellationToken = default);

    Task BindCertificateAsync(
        Guid certificateId,
        string hostname,
        CertificatePurpose purpose = CertificatePurpose.All,
        bool makeDefault = false,
        CancellationToken cancellationToken = default);

    Task UnbindCertificateAsync(Guid bindingId, CancellationToken cancellationToken = default);

    Task SetDefaultBindingAsync(Guid bindingId, CancellationToken cancellationToken = default);

    Task DeleteCertificateAsync(Guid certificateId, CancellationToken cancellationToken = default);

    // ---- ACME / Let's Encrypt ---------------------------------------------------------------

    Task<AcmeStatusDto> GetAcmeStatusAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AcmeAccountDto>> GetAcmeAccountsAsync(
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AcmeOrderDto>> GetAcmeOrdersAsync(
        int limit = 25,
        CancellationToken cancellationToken = default);

    /// <summary>Runs the pre-flight checks without submitting anything to the CA.</summary>
    /// <remarks>Costs no rate-limit quota, which is the point of offering it separately.</remarks>
    Task<IReadOnlyList<PreflightFindingDto>> CheckIssuanceReadinessAsync(
        IReadOnlyList<string> hostnames,
        AcmeChallengeType? challengeType = null,
        CancellationToken cancellationToken = default);

    Task<IssuanceResultDto> RequestCertificateAsync(
        IReadOnlyList<string> hostnames,
        AcmeChallengeType? challengeType = null,
        bool bindOnSuccess = true,
        CancellationToken cancellationToken = default);

    // ---- Mailboxes and aliases --------------------------------------------------------------

    Task<IReadOnlyList<MailboxSummaryDto>> GetMailboxesAsync(
        Guid domainId,
        CancellationToken cancellationToken = default);

    Task<MailboxDetailDto> GetMailboxAsync(
        Guid mailboxId,
        CancellationToken cancellationToken = default);

    /// <summary>Creates a mailbox.</summary>
    /// <remarks>
    /// The password is a method argument, never a property on a view model and never bound to
    /// a control — for the same reason the master password is not. A bound property outlives
    /// the operation, and everything that can reach it is one more place it can leak.
    /// </remarks>
    Task<MailboxSummaryDto> CreateMailboxAsync(
        Guid domainId,
        string localPart,
        string? displayName,
        string? password,
        long quotaBytes = 0,
        MailboxAccess access = MailboxAccess.Imap | MailboxAccess.Submission,
        CancellationToken cancellationToken = default);

    Task UpdateMailboxAsync(
        UpdateMailboxCommand command,
        CancellationToken cancellationToken = default);

    Task SetMailboxPasswordAsync(
        Guid mailboxId,
        string password,
        bool mustChange = true,
        CancellationToken cancellationToken = default);

    Task DeleteMailboxAsync(Guid mailboxId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<MissingRoleAddressDto>> GetMissingRoleAddressesAsync(
        Guid domainId,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AliasDto>> GetAliasesAsync(
        Guid domainId,
        CancellationToken cancellationToken = default);

    Task<AliasDto> CreateAliasAsync(
        Guid domainId,
        string localPart,
        IReadOnlyList<string> targets,
        string? description = null,
        CancellationToken cancellationToken = default);

    Task UpdateAliasAsync(UpdateAliasCommand command, CancellationToken cancellationToken = default);

    Task DeleteAliasAsync(Guid aliasId, CancellationToken cancellationToken = default);

    // ---- Deliverability ---------------------------------------------------------------------

    /// <summary>Runs every readiness check and returns the scored report with its evidence.</summary>
    Task<DeliverabilityReportDto> GetDeliverabilityReportAsync(
        string domain,
        CancellationToken cancellationToken = default);

    /// <summary>Writes the DNS records a domain needs, and the caveats no record discharges.</summary>
    Task<DnsPlanDto> GetDnsPlanAsync(
        string domain,
        string? dmarcReportAddress = null,
        string? tlsReportAddress = null,
        string? mtaStsId = null,
        CancellationToken cancellationToken = default);

    /// <summary>Re-evaluates a pasted header block, doing its own lookups.</summary>
    Task<HeaderAnalysisDto> AnalyseHeadersAsync(
        string headers,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Sends one real message to a nominated address and reports the conversation.
    /// </summary>
    /// <remarks>
    /// Unlike every other call here this one <i>emits traffic</i> from this server's IP, which
    /// is why the service puts it behind the write-level mail-flow permission rather than the
    /// read-only one the other deliverability calls use.
    /// </remarks>
    Task<DeliveryTestDto> RunDeliveryTestAsync(
        string sender,
        string recipient,
        bool requireTls = false,
        CancellationToken cancellationToken = default);

    /// <summary>Reads an RFC 8460 TLS report and says what it means.</summary>
    Task<TlsReportDto> AnalyseTlsReportAsync(
        string report,
        CancellationToken cancellationToken = default);
}

/// <summary>Implements <see cref="IAdminGateway"/> over <see cref="IpcClient"/>.</summary>
public sealed class AdminGateway(IpcClient client) : IAdminGateway
{
    public bool HasSession => client.HasSession;

    public async Task<SetupStatusDto> GetSetupStatusAsync(
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetSetupStatusQuery, SetupStatusDto>(
                "Security.SetupStatus",
                new GetSetupStatusQuery(),
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException("The service returned an empty setup status.");

    public async Task<SetupResultDto> CompleteSetupAsync(
        string password,
        string confirmPassword,
        CancellationToken cancellationToken = default)
    {
        SetupResultDto result = await client
            .SendAsync<CompleteSetupCommand, SetupResultDto>(
                "Security.CompleteSetup",
                new CompleteSetupCommand
                {
                    Password = password,
                    ConfirmPassword = confirmPassword,
                    Origin = DescribeOrigin(),
                },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("The service returned an empty setup result.");

        // Setup signs the administrator in, so adopt the session immediately.
        client.SetSessionToken(result.Authentication.SessionToken);

        return result;
    }

    public async Task<AuthenticationResultDto> AuthenticateAsync(
        string password,
        CancellationToken cancellationToken = default)
    {
        // Any previous token is discarded first. Retrying a sign-in while holding a dead token
        // would attach it to the request and generate a spurious invalid-session event.
        client.ClearSessionToken();

        AuthenticationResultDto result = await client
            .SendAsync<AuthenticateCommand, AuthenticationResultDto>(
                "Security.Authenticate",
                new AuthenticateCommand { Password = password, Origin = DescribeOrigin() },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("The service returned an empty sign-in result.");

        client.SetSessionToken(result.SessionToken);

        return result;
    }

    public async Task<RecoveryKeyDto> ResetPasswordWithRecoveryKeyAsync(
        string recoveryKey,
        string newPassword,
        string confirmNewPassword,
        CancellationToken cancellationToken = default)
    {
        client.ClearSessionToken();

        return await client
            .SendAsync<ResetPasswordWithRecoveryKeyCommand, RecoveryKeyDto>(
                "Security.ResetPasswordWithRecoveryKey",
                new ResetPasswordWithRecoveryKeyCommand
                {
                    RecoveryKey = recoveryKey,
                    NewPassword = newPassword,
                    ConfirmNewPassword = confirmNewPassword,
                    Origin = DescribeOrigin(),
                },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("The service returned an empty recovery result.");
    }

    public async Task SignOutAsync(
        bool isAutoLock = false,
        CancellationToken cancellationToken = default)
    {
        try
        {
            await client
                .SendAsync<SignOutCommand, Unit>(
                    "Security.SignOut",
                    new SignOutCommand { IsAutoLock = isAutoLock },
                    cancellationToken: cancellationToken)
                .ConfigureAwait(false);
        }
        catch (IpcRequestException)
        {
            // The session may already be gone - that is exactly when sign-out is most likely
            // to be called. Failing to tell the server about a session it has already forgotten
            // must not stop the console from locking locally.
        }
        finally
        {
            client.ClearSessionToken();
        }
    }

    public async Task ChangeMasterPasswordAsync(
        string currentPassword,
        string newPassword,
        string confirmNewPassword,
        bool keepOtherSessions = false,
        CancellationToken cancellationToken = default)
    {
        await client
            .SendAsync<ChangeMasterPasswordCommand, Unit>(
                "Security.ChangeMasterPassword",
                new ChangeMasterPasswordCommand
                {
                    CurrentPassword = currentPassword,
                    NewPassword = newPassword,
                    ConfirmNewPassword = confirmNewPassword,
                    KeepOtherSessions = keepOtherSessions,
                },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        if (!keepOtherSessions)
        {
            // The server revoked every session including this one. Drop the token so the UI
            // returns to the sign-in screen rather than discovering it one request later.
            client.ClearSessionToken();
        }
    }

    public async Task<SecurityStatusDto> GetSecurityStatusAsync(
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetSecurityStatusQuery, SecurityStatusDto>(
                "Security.Status",
                new GetSecurityStatusQuery(),
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException("The service returned an empty security status.");

    public async Task<IReadOnlyList<AdminSessionDto>> GetActiveSessionsAsync(
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetActiveSessionsQuery, IReadOnlyList<AdminSessionDto>>(
                "Security.Sessions",
                new GetActiveSessionsQuery(),
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? [];

    public async Task RevokeSessionAsync(
        Guid sessionId,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<RevokeSessionCommand, Unit>(
                "Security.RevokeSession",
                new RevokeSessionCommand { SessionId = sessionId },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    public async Task<PagedResult<AuditRecordDto>> GetAuditLogAsync(
        GetAuditLogQuery query,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        return await client
            .SendAsync<GetAuditLogQuery, PagedResult<AuditRecordDto>>(
                "Security.AuditLog",
                query,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
            ?? PagedResult<AuditRecordDto>.Empty(query.PageSize);
    }

    public async Task<PagedResult<SecurityEventDto>> GetSecurityEventsAsync(
        GetSecurityEventsQuery query,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        return await client
            .SendAsync<GetSecurityEventsQuery, PagedResult<SecurityEventDto>>(
                "Security.Events",
                query,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
            ?? PagedResult<SecurityEventDto>.Empty(query.PageSize);
    }

    /// <summary>
    /// Describes where this console is running, for the security event log.
    /// </summary>
    /// <remarks>
    /// Client-supplied and therefore untrusted — the server truncates it and never treats it as
    /// an identity. It is a convenience for reading the log ("which machine was that from?"),
    /// not an authentication factor. The authoritative origin is the Windows identity the
    /// server reads from the pipe itself.
    /// </remarks>
    private static string DescribeOrigin() =>
        $"{Environment.UserName}@{Environment.MachineName}";

    public async Task<SmtpStatusDto> GetSmtpStatusAsync(CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetSmtpStatusQuery, SmtpStatusDto>(
                "Smtp.Status",
                new GetSmtpStatusQuery(),
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException("The service returned an empty SMTP status payload.");

    public async Task<PagedResult<ReceivedMessageDto>> GetReceivedMessagesAsync(
        GetReceivedMessagesQuery query,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetReceivedMessagesQuery, PagedResult<ReceivedMessageDto>>(
                "Smtp.Received",
                query,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? PagedResult<ReceivedMessageDto>.Empty();

    public async Task<DashboardDto> GetDashboardAsync(CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetDashboardQuery, DashboardDto>(
                "Monitoring.Dashboard",
                new GetDashboardQuery(),
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException("The service returned an empty dashboard payload.");

    public async Task<PagedResult<DomainSummaryDto>> GetDomainsAsync(
        GetDomainsQuery query,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        return await client
            .SendAsync<GetDomainsQuery, PagedResult<DomainSummaryDto>>(
                "Domains.List",
                query,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
            ?? PagedResult<DomainSummaryDto>.Empty(query.PageSize);
    }

    public async Task<DomainDetailDto> GetDomainAsync(
        Guid domainId,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetDomainDetailsQuery, DomainDetailDto>(
                "Domains.Get",
                new GetDomainDetailsQuery { DomainId = domainId },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException("The service returned an empty domain payload.");

    public async Task<DomainSummaryDto> CreateDomainAsync(
        CreateDomainCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        return await client
            .SendAsync<CreateDomainCommand, DomainSummaryDto>(
                "Domains.Create",
                command,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("The service returned an empty domain payload.");
    }

    public async Task UpdateDomainAsync(
        UpdateDomainCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        await client
            .SendAsync<UpdateDomainCommand, Unit>("Domains.Update", command, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task SetDomainStatusAsync(
        Guid domainId,
        bool enabled,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<SetDomainStatusCommand, Unit>(
                "Domains.SetStatus",
                new SetDomainStatusCommand { DomainId = domainId, Enabled = enabled },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    public async Task DeleteDomainAsync(
        Guid domainId,
        bool permanently,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<DeleteDomainCommand, Unit>(
                "Domains.Delete",
                new DeleteDomainCommand { DomainId = domainId, PermanentlyDelete = permanently },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    // ---- Certificates ---------------------------------------------------------------------

    public async Task<IReadOnlyList<CertificateDto>> GetCertificatesAsync(
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetCertificatesQuery, IReadOnlyList<CertificateDto>>(
                "Certificates.List",
                new GetCertificatesQuery(),
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException(
            "The service returned an empty certificate list payload.");

    public async Task<CertificateDto> GetCertificateAsync(
        Guid certificateId,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetCertificateQuery, CertificateDto>(
                "Certificates.Get",
                new GetCertificateQuery { CertificateId = certificateId },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException(
            "The service returned an empty certificate payload.");

    public async Task<CertificateHealthDto> GetCertificateHealthAsync(
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetCertificateHealthQuery, CertificateHealthDto>(
                "Certificates.Health",
                new GetCertificateHealthQuery(),
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException(
            "The service returned an empty certificate health payload.");

    public async Task<IReadOnlyList<AvailableStoreCertificateDto>> GetAvailableStoreCertificatesAsync(
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetAvailableStoreCertificatesQuery, IReadOnlyList<AvailableStoreCertificateDto>>(
                "Certificates.AvailableInStore",
                new GetAvailableStoreCertificatesQuery(),
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException(
            "The service returned an empty store certificate payload.");

    /// <summary>
    /// Generates a self-signed certificate.
    /// </summary>
    /// <remarks>
    /// The returned DTO carries <c>IsSelfSigned</c>; every surface that displays the result
    /// must show <c>CertificateRenewalPolicy.SelfSignedWarning</c> verbatim.
    /// </remarks>
    public async Task<CertificateDto> GenerateSelfSignedCertificateAsync(
        IReadOnlyList<string> hostnames,
        int keySizeBits = 3072,
        int validityYears = 1,
        bool makeDefault = false,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GenerateSelfSignedCertificateCommand, CertificateDto>(
                "Certificates.GenerateSelfSigned",
                new GenerateSelfSignedCertificateCommand
                {
                    Hostnames = hostnames,
                    KeySizeBits = keySizeBits,
                    ValidityYears = validityYears,
                    MakeDefault = makeDefault,
                },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException(
            "The service returned an empty certificate payload.");

    /// <summary>Imports a PKCS#12 certificate.</summary>
    /// <remarks>
    /// The passphrase is a method argument and is never held on a view model or bound to a
    /// control, for the same reason master passwords are not: a bound property outlives the
    /// operation, and everything that can reach it is one more place it can leak.
    /// </remarks>
    public async Task<CertificateDto> ImportCertificateAsync(
        byte[] pfxBytes,
        string? passphrase,
        string? bindToHostname,
        bool makeDefault = false,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<ImportCertificateCommand, CertificateDto>(
                "Certificates.Import",
                new ImportCertificateCommand
                {
                    PfxBytes = pfxBytes,
                    Passphrase = passphrase,
                    BindToHostname = bindToHostname,
                    MakeDefault = makeDefault,
                },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException(
            "The service returned an empty certificate payload.");

    public async Task<CertificateDto> AdoptStoreCertificateAsync(
        string thumbprint,
        string? bindToHostname,
        bool makeDefault = false,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<AdoptStoreCertificateCommand, CertificateDto>(
                "Certificates.AdoptFromStore",
                new AdoptStoreCertificateCommand
                {
                    Thumbprint = thumbprint,
                    BindToHostname = bindToHostname,
                    MakeDefault = makeDefault,
                },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException(
            "The service returned an empty certificate payload.");

    public async Task BindCertificateAsync(
        Guid certificateId,
        string hostname,
        CertificatePurpose purpose = CertificatePurpose.All,
        bool makeDefault = false,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<BindCertificateCommand, Unit>(
                "Certificates.Bind",
                new BindCertificateCommand
                {
                    CertificateId = certificateId,
                    Hostname = hostname,
                    Purpose = purpose,
                    MakeDefault = makeDefault,
                },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    public async Task UnbindCertificateAsync(
        Guid bindingId,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<UnbindCertificateCommand, Unit>(
                "Certificates.Unbind",
                new UnbindCertificateCommand { BindingId = bindingId },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    public async Task SetDefaultBindingAsync(
        Guid bindingId,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<SetDefaultBindingCommand, Unit>(
                "Certificates.SetDefaultBinding",
                new SetDefaultBindingCommand { BindingId = bindingId },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    public async Task DeleteCertificateAsync(
        Guid certificateId,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<DeleteCertificateCommand, Unit>(
                "Certificates.Delete",
                new DeleteCertificateCommand { CertificateId = certificateId },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    // ---- ACME / Let's Encrypt ---------------------------------------------------------------

    public async Task<AcmeStatusDto> GetAcmeStatusAsync(
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetAcmeStatusQuery, AcmeStatusDto>(
                "Acme.Status",
                new GetAcmeStatusQuery(),
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException(
            "The service returned an empty ACME status payload.");

    public async Task<IReadOnlyList<AcmeAccountDto>> GetAcmeAccountsAsync(
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetAcmeAccountsQuery, IReadOnlyList<AcmeAccountDto>>(
                "Acme.Accounts",
                new GetAcmeAccountsQuery(),
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException(
            "The service returned an empty ACME account payload.");

    public async Task<IReadOnlyList<AcmeOrderDto>> GetAcmeOrdersAsync(
        int limit = 25,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetAcmeOrdersQuery, IReadOnlyList<AcmeOrderDto>>(
                "Acme.Orders",
                new GetAcmeOrdersQuery { Limit = limit },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException(
            "The service returned an empty ACME order payload.");

    public async Task<IReadOnlyList<PreflightFindingDto>> CheckIssuanceReadinessAsync(
        IReadOnlyList<string> hostnames,
        AcmeChallengeType? challengeType = null,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<CheckIssuanceReadinessCommand, IReadOnlyList<PreflightFindingDto>>(
                "Acme.CheckReadiness",
                new CheckIssuanceReadinessCommand
                {
                    Hostnames = hostnames,
                    ChallengeType = challengeType,
                },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException(
            "The service returned an empty pre-flight payload.");

    /// <remarks>
    /// The request timeout is the client's default, which can be shorter than an issuance
    /// takes: the CA's validation is polled for up to five minutes. A caller that times out has
    /// not cancelled anything — the order continues server-side, and its outcome appears in
    /// <see cref="GetAcmeOrdersAsync"/>.
    /// </remarks>
    public async Task<IssuanceResultDto> RequestCertificateAsync(
        IReadOnlyList<string> hostnames,
        AcmeChallengeType? challengeType = null,
        bool bindOnSuccess = true,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<RequestCertificateCommand, IssuanceResultDto>(
                "Acme.RequestCertificate",
                new RequestCertificateCommand
                {
                    Hostnames = hostnames,
                    ChallengeType = challengeType,
                    BindOnSuccess = bindOnSuccess,
                },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException(
            "The service returned an empty issuance payload.");

    // ---- Mailboxes and aliases --------------------------------------------------------------

    public async Task<IReadOnlyList<MailboxSummaryDto>> GetMailboxesAsync(
        Guid domainId,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetMailboxesQuery, IReadOnlyList<MailboxSummaryDto>>(
                "Mailboxes.List",
                new GetMailboxesQuery { DomainId = domainId },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException("The service returned an empty mailbox payload.");

    public async Task<MailboxDetailDto> GetMailboxAsync(
        Guid mailboxId,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetMailboxQuery, MailboxDetailDto>(
                "Mailboxes.Get",
                new GetMailboxQuery { MailboxId = mailboxId },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException("The service returned an empty mailbox payload.");

    public async Task<MailboxSummaryDto> CreateMailboxAsync(
        Guid domainId,
        string localPart,
        string? displayName,
        string? password,
        long quotaBytes = 0,
        MailboxAccess access = MailboxAccess.Imap | MailboxAccess.Submission,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<CreateMailboxCommand, MailboxSummaryDto>(
                "Mailboxes.Create",
                new CreateMailboxCommand
                {
                    DomainId = domainId,
                    LocalPart = localPart,
                    DisplayName = displayName,
                    Password = password,
                    QuotaBytes = quotaBytes,
                    Access = access,
                },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException("The service returned an empty mailbox payload.");

    public async Task UpdateMailboxAsync(
        UpdateMailboxCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        await client
            .SendAsync<UpdateMailboxCommand, Unit>(
                "Mailboxes.Update",
                command,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task SetMailboxPasswordAsync(
        Guid mailboxId,
        string password,
        bool mustChange = true,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<SetMailboxPasswordCommand, Unit>(
                "Mailboxes.SetPassword",
                new SetMailboxPasswordCommand
                {
                    MailboxId = mailboxId,
                    Password = password,
                    MustChange = mustChange,
                },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    public async Task DeleteMailboxAsync(
        Guid mailboxId,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<DeleteMailboxCommand, Unit>(
                "Mailboxes.Delete",
                new DeleteMailboxCommand { MailboxId = mailboxId },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    public async Task<IReadOnlyList<MissingRoleAddressDto>> GetMissingRoleAddressesAsync(
        Guid domainId,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetMissingRoleAddressesQuery, IReadOnlyList<MissingRoleAddressDto>>(
                "Mailboxes.RoleAddresses",
                new GetMissingRoleAddressesQuery { DomainId = domainId },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException("The service returned an empty role-address payload.");

    public async Task<IReadOnlyList<AliasDto>> GetAliasesAsync(
        Guid domainId,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetAliasesQuery, IReadOnlyList<AliasDto>>(
                "Aliases.List",
                new GetAliasesQuery { DomainId = domainId },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException("The service returned an empty alias payload.");

    public async Task<AliasDto> CreateAliasAsync(
        Guid domainId,
        string localPart,
        IReadOnlyList<string> targets,
        string? description = null,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<CreateAliasCommand, AliasDto>(
                "Aliases.Create",
                new CreateAliasCommand
                {
                    DomainId = domainId,
                    LocalPart = localPart,
                    Targets = targets,
                    Description = description,
                },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException("The service returned an empty alias payload.");

    public async Task UpdateAliasAsync(
        UpdateAliasCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        await client
            .SendAsync<UpdateAliasCommand, Unit>(
                "Aliases.Update",
                command,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task DeleteAliasAsync(
        Guid aliasId,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<DeleteAliasCommand, Unit>(
                "Aliases.Delete",
                new DeleteAliasCommand { AliasId = aliasId },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    // ---- Deliverability ---------------------------------------------------------------------

    public async Task<DeliverabilityReportDto> GetDeliverabilityReportAsync(
        string domain,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetDeliverabilityReportQuery, DeliverabilityReportDto>(
                "Deliverability.Report",
                new GetDeliverabilityReportQuery { Domain = domain },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException(
            "The service returned an empty deliverability report.");

    public async Task<DnsPlanDto> GetDnsPlanAsync(
        string domain,
        string? dmarcReportAddress = null,
        string? tlsReportAddress = null,
        string? mtaStsId = null,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<GetDnsPlanQuery, DnsPlanDto>(
                "Deliverability.DnsPlan",
                new GetDnsPlanQuery
                {
                    Domain = domain,
                    DmarcReportAddress = dmarcReportAddress,
                    TlsReportAddress = tlsReportAddress,
                    MtaStsId = mtaStsId,
                },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException("The service returned an empty DNS plan.");

    public async Task<HeaderAnalysisDto> AnalyseHeadersAsync(
        string headers,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<AnalyseHeadersQuery, HeaderAnalysisDto>(
                "Deliverability.AnalyseHeaders",
                new AnalyseHeadersQuery { Headers = headers },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException("The service returned an empty header analysis.");

    public async Task<DeliveryTestDto> RunDeliveryTestAsync(
        string sender,
        string recipient,
        bool requireTls = false,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<RunDeliveryTestCommand, DeliveryTestDto>(
                "Deliverability.DeliveryTest",
                new RunDeliveryTestCommand
                {
                    Sender = sender,
                    Recipient = recipient,
                    RequireTls = requireTls,
                },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException("The service returned an empty delivery test result.");

    public async Task<TlsReportDto> AnalyseTlsReportAsync(
        string report,
        CancellationToken cancellationToken = default) =>
        await client
            .SendAsync<AnalyseTlsReportQuery, TlsReportDto>(
                "Deliverability.AnalyseTlsReport",
                new AnalyseTlsReportQuery { Report = report },
                cancellationToken: cancellationToken)
            .ConfigureAwait(false)
        ?? throw new InvalidOperationException("The service returned an empty TLS report analysis.");
}
