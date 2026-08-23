# TenantWatch — Install & Credentials

TenantWatch reads your tenant **read-only**. You grant it read-only credentials once; it stores them on your server and never sends them anywhere. This guide sets up the two providers.

## 1. Run it

```sh
tar xzf tenantwatch-0.1.0-linux-amd64.tar.gz && cd tenantwatch-0.1.0
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
5. Put the tenant id, client id and secret into `tenants.json` under `m365`.

No write permission is requested at any point. Conditional-access and sign-in-activity checks need Entra ID P1; without it those areas report as *manual review* rather than failing.

## 3. Google Workspace — service account with read-only delegation

1. In **Google Cloud Console**, create a project and a **Service Account**. Create a **JSON key** and save it (this is `service_account_json`).
2. Enable the **Admin SDK API** for the project.
3. In the service account's **Domain-wide delegation**, note its **Client ID**.
4. In the **Google Workspace Admin console → Security → API controls → Domain-wide delegation**, add that Client ID with this **read-only** scope:
   - `https://www.googleapis.com/auth/admin.directory.user.readonly`
5. Set `admin_email` to a super-admin the service account may impersonate (read-only), and `service_account_json` to the key file path.

## 4. Keep it running

- Run under systemd or in Docker (`docker build -t tenantwatch .`). Bind to `127.0.0.1` and reverse-proxy if you need remote access.
- Scans run automatically every 12 hours; Pro/Team can trigger **Scan now**.
- Alerts: `-webhook https://…` for any receiver, or `-syslog host:5514` to forward findings (point it at Loglight to correlate).

## Air-gapped / restricted egress

TenantWatch must reach `graph.microsoft.com` / `admin.googleapis.com` to read the tenant, and public DNS for email-auth. If DNS is blocked, the email-authentication check is skipped (no false findings). Everything else stays local.
