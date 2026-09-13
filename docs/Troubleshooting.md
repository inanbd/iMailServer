# Troubleshooting

## The service will not start

The service **deliberately refuses to start** on several conditions rather than running in a
subtly wrong state. Each message says what to do.

| Message | Cause | Fix |
|---|---|---|
| `Hostname '…' is not a valid fully-qualified domain name` | `MailServer:Server:Hostname` is a bare name like `localhost` | Set a real FQDN with a matching PTR record. This name is announced in EHLO |
| `Migration NNNN '…' has already been applied, but the script on disk no longer matches` | Schema drift: an applied migration was edited | Restore the original script, or add a new migration. **Never** edit an applied one |
| `SecretProtection is 'Development' but the environment is Production` | Development protector in production | Set it to `Dpapi` |
| `SecretProtection is 'Dpapi', which requires Windows` | DPAPI on a non-Windows machine | Use `Development` and keep the environment out of Production |
| `ConnectionString must not be used in Production` | A SQL credential in a JSON file | Move it to the secret store and use `ConnectionStringSecretName` |
| `Message storage at '…' could not be prepared` | Path invalid or not writable by the service account | Fix the path or the ACL |

Structured logs are under `Data/Logs/aethermail-YYYYMMDD.log`.

---

## Mail is not being delivered to the Internet

### First: is outbound port 25 even available?

**This is the single most common cause, and it is usually not fixable in software.**

* **Azure** blocks outbound 25 on almost all subscriptions, with no exception process for most
  account types.
* **AWS and GCP** block it by default and require a request.
* **Nearly all residential ISPs** block it permanently.

Test from the server itself:

```bash
# Should connect and show a 220 banner
Test-NetConnection gmail-smtp-in.l.google.com -Port 25      # PowerShell
nc -vz gmail-smtp-in.l.google.com 25                        # bash
```

If it does not connect, direct MX delivery is impossible from that host. Configure a smarthost
relay — `MailServer:Delivery:Mode = SmartHost` — which is a fully supported mode, not a
consolation prize.

### Then: DNS

```bash
dig +short MX example.com
dig +short A  mail.example.com
dig +short -x 203.0.113.10        # PTR — must return mail.example.com
```

PTR is configured by **the IP owner** — your hosting provider, datacentre or ISP — never in
your own zone. If they will not set it, you cannot run a public mail server on that IP.

---

## Gmail or Microsoft 365 sends everything to spam

Work through, in order:

1. **FCrDNS.** PTR resolves to your hostname, and that hostname resolves back to the same IP.
   Non-negotiable.
2. **SPF passes and aligns.** Send to a Gmail account and read the `Authentication-Results`
   header it adds.
3. **DKIM passes and aligns.** Same header.
4. **DMARC passes.** At least one of SPF or DKIM must be *aligned*, not merely passing.
5. **TLS certificate is publicly trusted** and covers the EHLO hostname.
6. **The IP has no history.** Check whether it was used for spam before you got it.
7. **Sending volume and pattern.** A new IP sending thousands of messages on day one looks
   exactly like a compromised host.

If 1–6 are all correct, the remaining answer is time. Reputation accumulates over weeks; see
`docs/Deliverability.md`.

Microsoft 365 is the hardest receiver: it throttles unknown senders aggressively and its
delisting process is manual. Expect deferrals early on, and let the per-domain throttling back
off rather than retrying harder.

---

## Certificate problems

| Symptom | Cause |
|---|---|
| Clients warn about the certificate | Self-signed, or the SAN does not cover the name the client used |
| ACME validation fails on HTTP-01 | Port 80 blocked, or DNS not pointing here. Test from **outside** your network |
| ACME validation fails on DNS-01 | Record not propagated. Query the **authoritative** servers, not your local resolver |
| "too many certificates already issued" | Rate limit. Wait. Use staging for further testing |
| Renewal keeps failing | The existing certificate is kept and health escalates — check the log for the CA's actual reason |

The server will **never** replace a valid public certificate with a self-signed one on renewal
failure. If TLS suddenly breaks after a renewal window, the cause is something else.

---

## Database problems

**`SQLITE_BUSY` under load.** The in-process write gate should prevent this. If it appears,
something is writing outside the gate — a second process, or a code path opening its own
connection rather than going through `ITransactionManager`.

**Deadlocks on SQL Server.** `READ_COMMITTED_SNAPSHOT` should prevent reader/writer deadlocks.
Confirm it is actually on:

```sql
SELECT is_read_committed_snapshot_on FROM sys.databases WHERE name = DB_NAME();
```

**Verify SQLite pragmas actually applied** — both fail silently:

```sql
PRAGMA journal_mode;   -- must be: wal
PRAGMA foreign_keys;   -- must be: 1
```

---

## The admin application cannot connect

1. Is the service running?
2. Is the pipe name identical on both sides — `MailServer:Ipc:PipeName` and the admin app's
   `Admin:PipeName`?
3. **Is the admin application elevated?** The pipe ACL admits only the local Administrators
   group and the service account. An unelevated process cannot connect at all.
4. Is `Admin:ServerName` correct? `.` is the local machine.

A protocol-mismatch error means the two were built from different versions; upgrade the admin
application to match the service.

---

## Reading the logs

Every log line carries a correlation id. An error shown in the admin UI includes that id, so:

```bash
grep "01J9Z8Q7XKACME000000000001" Data/Logs/aethermail-*.log
```

returns every line from that one operation, across the pipeline and, from Milestone 8, across
the delivery attempt as well.
