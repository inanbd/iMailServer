using MailServer.Application.Abstractions.Messaging;
using MailServer.Application.Abstractions.Monitoring;
using MailServer.Application.Abstractions.Persistence;
using MailServer.Application.Abstractions.Queries;
using MailServer.Application.Abstractions.Platform;
using MailServer.Application.Abstractions.Time;
using MailServer.Application.Monitoring.Dtos;
using MailServer.Domain.Enums;
using MediatR;
using Microsoft.Extensions.Logging;

namespace MailServer.Application.Monitoring.Queries;

/// <summary>Returns the dashboard read model.</summary>
public sealed record GetDashboardQuery : IQuery<DashboardDto>, IAuthorizedRequest
{
    public AdminPermission RequiredPermission => AdminPermission.ViewServerState;
}

internal sealed class GetDashboardQueryHandler(
    IServerStatusQueries statusQueries,
    IHealthRegistry health,
    IMaintenanceModeAccessor maintenanceMode,
    IEnvironmentInfo environment,
    ISqlDialect dialect,
    IServerIdentityProvider serverIdentity,
    IClock clock,
    ILogger<GetDashboardQueryHandler> logger)
    : IRequestHandler<GetDashboardQuery, DashboardDto>
{
    public async Task<DashboardDto> Handle(
        GetDashboardQuery request,
        CancellationToken cancellationToken)
    {
        ServerCountersDto counters;
        try
        {
            counters = await statusQueries.GetCountersAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // A dashboard that goes blank when the database hiccups is worse than one that
            // shows zeroes plus a Critical health indicator, because the health indicator is
            // the thing the operator actually needs to see at that moment.
            logger.LogError(ex, "Dashboard counters could not be read.");

            counters = new ServerCountersDto
            {
                DomainCount = 0,
                ActiveDomainCount = 0,
                MailboxCount = 0,
                QueuedMessageCount = 0,
                DeferredMessageCount = 0,
                StorageUsedBytes = 0,
            };
        }

        IReadOnlyList<HealthComponentDto> components =
        [
            .. health.GetAll()
                .OrderBy(r => r.Component, StringComparer.OrdinalIgnoreCase)
                .Select(r => new HealthComponentDto
                {
                    Component = r.Component,
                    State = r.State,
                    Message = r.Message,
                    ObservedUtc = r.ObservedUtc,
                })
        ];

        return new DashboardDto
        {
            Counters = counters,
            Health = components,
            OverallHealth = health.GetOverallState(),
            MaintenanceMode = maintenanceMode.Current,
            ServerHostname = serverIdentity.Hostname,
            DatabaseProvider = dialect.Name,
            ProductVersion = environment.ProductVersion,
            GeneratedUtc = clock.UtcNow,
        };
    }
}
