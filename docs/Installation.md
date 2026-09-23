# Installation

> **Status: the WiX installer and first-run wizard arrive in Milestone 13.** What follows is
> the current developer and evaluation procedure, plus the design the installer will follow.

## Requirements

| | |
|---|---|
| OS | Windows Server 2019 / 2022 / 2025, x64 |
| Runtime | .NET 10 (the installer will carry it) |
| Database | SQLite (bundled) or SQL Server 2019+ |
| Network | Static public IP, PTR control, inbound and outbound TCP 25 |

See `docs/Troubleshooting.md` before committing to a host — outbound port 25 is blocked on
most cloud providers.

## Ports

Open only what is enabled. The installer creates Windows Firewall rules for the services
actually turned on, not for all of them.

| Port | Service | Needed when |
|---|---|---|
| 25 | SMTP inbound | Receiving Internet mail |
| 80 | HTTP | ACME HTTP-01 challenges, HTTPS redirect |
| 443 | HTTPS | MTA-STS policy, management endpoints |
| 465 | SMTP implicit TLS | Client submission |
| 587 | SMTP submission | Client submission |
| 993 | IMAPS | Mailbox access |
| 995 | POP3S | Legacy only, off by default |

## Running from source

```powershell
git clone https://github.com/inanbd/iMailServer.git
cd iMailServer

dotnet build MailServer.sln -c Release
dotnet test  MailServer.sln -c Release

cd src\MailServer.Service
dotnet run -- --MailServer:Storage:DataRoot=C:\ProgramData\AetherMail\Data
```

### Install as a Windows Service

```powershell
dotnet publish src\MailServer.Service -c Release -o C:\Program Files\AetherMail

sc.exe create AetherMailServer `
    binPath= "C:\Program Files\AetherMail\MailServer.Service.exe" `
    DisplayName= "AetherMail Server" `
    start= auto

# Restart on failure rather than staying down until somebody notices
sc.exe failure AetherMailServer reset= 86400 actions= restart/60000/restart/120000/restart/300000

sc.exe start AetherMailServer
```

## Service account

**Do not use Domain Administrator, and do not use LocalSystem in production.**

Create a dedicated account with least privilege. It needs:

* Read and execute on the application directory
* Full control on the data root (`C:\ProgramData\AetherMail\Data`)
* Read access to the TLS certificate's private key container
* `db_datareader`, `db_datawriter`, `EXECUTE` and — for migrations — `db_ddladmin` on its
  database. **Not** `sysadmin`, **not** `db_owner`
* "Log on as a service"

It does **not** need local administrator rights.

## Directory layout

```text
C:\Program Files\AetherMail\          binaries — replaced on upgrade
C:\ProgramData\AetherMail\
    appsettings.machine.json          machine configuration — SURVIVES upgrade
    Data\
        Messages\  Queue\  Temp\      mail
        Certificates\                 keys and certificates
        Backups\  Logs\               operations
        Quarantine\  Reports\
```

Machine configuration lives under ProgramData precisely so that replacing the files in Program
Files during an upgrade does not lose it.

`Temp\` must be on the same volume as `Messages\` — `File.Move` across volumes is a copy, and
a copy is not atomic. `ServerPaths` has a test asserting this.

## Configuration

Precedence, lowest to highest:

```text
appsettings.json  →  appsettings.{Environment}.json
                  →  ProgramData\AetherMail\appsettings.machine.json
                  →  AETHERMAIL_ environment variables
                  →  command line
```

**Secrets never live in JSON.** Configuration holds only the *name* of a secret in the
DPAPI-protected store. In a Production environment the options validator refuses to start if a
SQL connection string is present inline.

### Minimum viable configuration

```jsonc
{
  "MailServer": {
    "Server": {
      "Hostname": "mail.example.com",       // must match PTR and the certificate SAN
      "PublicIpAddress": "203.0.113.10"
    },
    "Database": {
      "Provider": "Sqlite",
      "Sqlite": { "DataSource": "C:\\ProgramData\\AetherMail\\Data\\mailserver.db" }
    },
    "Storage": { "DataRoot": "C:\\ProgramData\\AetherMail\\Data" },
    "Security": { "SecretProtection": "Dpapi" }
  }
}
```

## Upgrading

1. Stop the service.
2. **Back up** — the database, the message store and the secrets. See `docs/BackupRestore.md`.
3. Replace the binaries.
4. Start the service. Migrations run automatically; a failure aborts startup and rolls back
   rather than leaving a half-migrated schema.
5. Check the log for the schema version and the health summary.

Upgrades never touch the data root except through migrations. A migration marked
`-- @Destructive` refuses to run unattended until backups exist.

## First-run administrator setup

The server ships with **no account and no default password**. The first time the administration
application connects, it presents a setup wizard that creates the single built-in administrator
and then displays a recovery key once.

```text
Connect → Choose master password (minimum 12 characters) → Recovery key shown once → Signed in
```

Three things matter here, and all three are deliberate:

* **Record the recovery key before continuing.** It is stored only as an Argon2id hash and
  cannot be redisplayed. There is no support backdoor and no file you can delete to reset the
  password. If the password and the key are both lost, the database must be recreated.
* **There are no composition rules.** Length is what is enforced (12 minimum, 256 maximum),
  following NIST SP 800-63B. A long passphrase is the recommended choice.
* **Being a local administrator is no longer sufficient.** Every launch after setup asks for
  the master password, and the pipe ACL is now defence in depth rather than the authorisation
  mechanism.

After five consecutive failures the account locks for 15 minutes, doubling at each further
multiple of five up to eight hours. The lock is recorded in the database, so restarting the
service does not clear it. Use the recovery key if you are locked out and need in now — it
deliberately bypasses the lockout.

---

## Adding a domain

Until the Milestone 13 wizard exists, a domain is added on the **Domains** page, and it does not
take mail the moment it is created. That is deliberate: a domain that sent mail before its DNS
and signing were in place would fail authentication at every major receiver and damage the
sending IP's reputation for weeks.

```text
Create (Pending) → Mail hostname set → DNS published → Enable (Active)
```

1. **Create it.** It starts **Pending**. Give it a **mail hostname** now if you know it — the
   name this server uses when it sends the domain's mail, which the reverse DNS and the
   certificate must match; on a single server it is usually the server's own hostname.
2. **Set the mail hostname if you skipped it.** A domain cannot be enabled without one. Select
   the domain and use the **Mail hostname** box; it changes nothing else about the domain.
3. **Publish its DNS.** Deliverability → Readiness builds the records for the domain and checks
   them once published.
4. **Enable it.** Only now does it accept mail and allow its mailboxes to send.

**What senders see while it is Pending.** Mail for the domain is answered
`450 4.3.2 ... this domain is not accepting mail yet; try again later`. Senders queue it and
retry for days, so mail that arrives early because the MX record was published first is
delivered once you enable the domain rather than bounced. The server log says which domain is
waiting and that it needs enabling.

**Disabling a domain is different.** A Disabled domain — or one marked for deletion — is refused
permanently, exactly as if it were not hosted here: that is the correct answer to "we no longer
take mail for this domain". Its mailboxes and stored mail are kept.

---

## The full first-run wizard (Milestone 13)

Sixteen steps, in this order, because each depends on the last:

```text
Welcome → Master password → Database → Storage → Hostname → Public IP
→ TLS method → First domain → Generate DKIM → DNS records → PTR guidance
→ Port testing → Certificate validation → Deliverability readiness
→ First mailbox → Finish
```

The recommended TLS choice is "Automatically obtain a trusted certificate from Let's Encrypt".

The wizard deliberately runs port testing and certificate validation **before** declaring the
server ready, so an operator learns that outbound 25 is blocked during setup rather than after
their first message silently fails to deliver.
