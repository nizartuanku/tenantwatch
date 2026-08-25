# TenantWatch — Install & Credentials

TenantWatch reads your tenant **read-only**. You grant it read-only credentials once; it stores them on your server and never sends them anywhere. This guide sets up the two providers.

## 1. Run it

```sh
tar xzf tenantwatch-0.2.0-linux-amd64.tar.gz && cd tenantwatch-0.2.0
cp tenants.example.json tenants.json
./tenantwatch -creds tenants.json          # dashboard on http://127.0.0.1:8430
```

`tenants.json` is where credentials live:

```json
{
  "m365": [
    {
      "domain": "contoso.onmicrosoft.com",
      "tenant_id": "00000000-0000-0000-0000-000000000000",
      "client_id": "11111111-1111-1111-1111-111111111111",
      "client_secret": "your-client-secret"
    }
  ],
  "gws": [
    {
      "domain": "contoso.co.id",
      "admin_email": "admin@contoso.co.id",
      "service_account_json": "/path/to/service-account.json"
    }
  ]
}
```

Then add the tenant in the dashboard as `m365:contoso.onmicrosoft.com` or `gws:contoso.co.id`.

## 2. Microsoft 365 — read-only app registration

1. In **Entra ID → App registrations → New registration**. Name it `TenantWatch (read-only)`.
2. Copy the **Application (client) ID** and **Directory (tenant) ID**.
3. **Certificates & secrets → New client secret**. Copy the value.
4. **API permissions → Add → Microsoft Graph → Application permissions**, add these read-only scopes, then **Grant admin consent**:
   - `User.Read.All`
   - `Directory.Read.All`
   - `RoleManagement.Read.Directory`
   - `Policy.Read.All`
   - `Reports.Read.All` (MFA registration state)
   - `Application.Read.All` (third-party app consents)
   - `AuditLog.Read.All` (**Sign-in Watch** — without this the sign-in checks cannot run)
5. Put the tenant id, client id and secret into `tenants.json` under `m365`.

No write permission is requested at any point.

**Sign-in Watch needs Microsoft Entra ID P1 or P2 as well as the permission.** Microsoft gates `/auditLogs/signIns` behind premium licensing, and P1 ships with Microsoft 365 **Business Premium** but *not* with Business Basic or Business Standard. Two different things can therefore block it, and TenantWatch tells you which:

| What you see in the dashboard | What it means | What to do |
|---|---|---|
| A note naming **Entra ID P1** and Business Premium | The licence is missing | Nothing to fix in the app registration — the tenant's plan does not include the log |
| A note naming **AuditLog.Read.All** and Directory.Read.All | The permission was not granted or consented | Add the scope above and click **Grant admin consent** |

Either way, every configuration check keeps working, and no sign-in check ever reports "clean" from a log it could not read. Conditional-access assessment also needs P1.

## 3. Google Workspace — service account with read-only delegation

1. In **Google Cloud Console**, create a project and a **Service Account**. Create a **JSON key** and save it (this is `service_account_json`).
2. Enable the **Admin SDK API** for the project (this covers both the Directory API and the Reports API).
3. In the service account's **Domain-wide delegation**, note its **Client ID**.
4. In the **Google Workspace Admin console → Security → API controls → Domain-wide delegation**, add that Client ID with these **read-only** scopes:
   - `https://www.googleapis.com/auth/admin.directory.user.readonly`
   - `https://www.googleapis.com/auth/admin.reports.audit.readonly` (**Sign-in Watch** — the login audit)
5. Set `admin_email` to a super-admin the service account may impersonate (read-only), and `service_account_json` to the key file path.

Unlike Microsoft, Google puts **no licence gate** on the login audit — the scope is all you need. But Google's audit reports no country per login and no per-event authentication strength, so `tenant.signin-country-hop` and `tenant.signin-admin-1fa` cannot run on Workspace at all. TenantWatch reports both as unassessed instead of pretending. Google's own `is_suspicious` verdict is surfaced as `tenant.signin-suspicious`.

## 4. Keep it running

- Run under systemd or in Docker (`docker build -t tenantwatch .`). Bind to `127.0.0.1` and reverse-proxy if you need remote access.
- Scans run automatically every 12 hours; Pro/Team can trigger **Scan now**.
- Alerts: `-webhook https://…` for any receiver, or `-syslog host:5514` to forward findings (point it at Loglight to correlate).

## Air-gapped / restricted egress

TenantWatch must reach `graph.microsoft.com` / `admin.googleapis.com` to read the tenant, and public DNS for email-auth. If DNS is blocked, the email-authentication check is skipped (no false findings). Everything else stays local.
