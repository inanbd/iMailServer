using MailServer.Application.Common;
using MailServer.Application.Domains.Commands;
using MailServer.Application.Domains.Dtos;
using MailServer.Application.Domains.Queries;
using MailServer.Application.Monitoring.Dtos;
using MailServer.Application.Monitoring.Queries;
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
}

/// <summary>Implements <see cref="IAdminGateway"/> over <see cref="IpcClient"/>.</summary>
public sealed class AdminGateway(IpcClient client) : IAdminGateway
{
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
}
