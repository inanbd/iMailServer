# Windows Server Deployment

## The service is the product

`MailServer.Service` owns every listener, queue, timer and certificate. `MailServer.Admin` is
a management console: closing it, uninstalling it, or leaving it locked has **no** effect on
mail flow.

This is stated in the admin application's own status strip, because an administrator who
believes closing the console stops mail will make bad decisions during an incident.

## Startup gates

Hosted services start in registration order and the host awaits each one. The first
registration is a gate:

```text
1. Configuration validation   → refuse to start on invalid configuration
2. Storage preparation        → create directories, verify ACLs and free space
3. Database migration         → apply pending migrations, or refuse to start
4. Maintenance mode           → restore the persisted operating mode
        ↓  only then
   Listeners and processors
```

Failing to start is the correct outcome for all three. A mail server that comes up against a
half-migrated schema accepts mail it cannot store and returns `250` for messages that are then
lost. Refusing to start is visible, diagnosable, and loses nothing.

## Workers

Every worker derives from `ResilientBackgroundService` rather than raw `BackgroundService`.

Since .NET 6, an unhandled exception in a `BackgroundService` stops the entire host by default.
For a mail server that is wrong by a wide margin: a transient DNS failure in the DNS monitor
must never stop SMTP receipt.

The base class provides fault isolation, restart with exponential backoff **and jitter**,
health reporting, graceful shutdown and maintenance-mode awareness. Jitter matters because
several workers usually depend on the same failing resource — the database — and without it
they synchronise onto the same retry instant and hammer a server that is trying to recover.

`OperationCanceledException` during shutdown is treated as success, never as a fault. Logging
clean shutdowns as errors trains operators to ignore exactly the messages they should not.

## Graceful shutdown

Order matters for data integrity:

```text
1. Stop accepting new SMTP/IMAP/POP3 connections
2. Reject new IPC commands with SERVICE_STOPPING
3. Drain in-flight inbound sessions (finish, or 451 them cleanly)
4. Let outbound deliveries in the DATA phase COMPLETE — do not abandon mid-DATA
5. Release queue leases so nothing is stranded
6. Flush metrics and logs
7. Close database connections
```

Step 4 is explicit: abandoning a delivery mid-`DATA` risks a duplicate at the remote server.

## Service recovery

```powershell
sc.exe failure AetherMailServer reset= 86400 `
    actions= restart/60000/restart/120000/restart/300000
```

Increasing delays, because a service that crashes on startup and restarts instantly produces a
tight loop that fills the event log and achieves nothing.

## Windows Event Log

Critical events only:

```text
Service started / stopped        Database unavailable
Certificate renewal failed       Certificate expired
Disk low                         Queue critically large
Backup failed                    Unexpected service failure
```

**Not** every SMTP transaction. The Event Log is for things an operator must notice; per-message
detail belongs in the structured log, where it can be filtered by correlation id.

## Firewall

The installer creates rules only for enabled services. A rule for POP3 on a server with POP3
disabled is an open port with nothing behind it — pure attack surface for no benefit.

## Hardening

* Dedicated least-privilege service account (see `docs/Installation.md`)
* SCHANNEL policy managed centrally, not hardcoded in the application
* The data root ACL'd to the service account and administrators only
* Certificate private keys not exported to disk when the certificate store holds them
* The IPC pipe restricted to local administrators, with `NETWORK` explicitly denied
* Automatic Windows Updates, with a maintenance window that pauses inbound mail rather than
  dropping connections mid-session

## Monitoring

The health registry exposes every subsystem with a four-state value — `Healthy`, `Warning`,
`Critical`, `Unknown` — and the same vocabulary is used everywhere in the product, so an
operator learns four words once.

Worth alerting on: overall health `Critical`, certificate expiry under 14 days, queue depth
trending up, disk below the configured minimum, clock skew, and any maintenance mode other
than `Normal` persisting longer than expected.
