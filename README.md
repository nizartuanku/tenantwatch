# TenantWatch

**Read-only security-posture auditing for Microsoft 365 and Google Workspace — self-hosted, no data leaves your network.**

Most small teams live entirely in M365 or Google Workspace and have never audited the security settings. TenantWatch connects read-only, checks the things that actually get organisations breached — accounts without MFA, over-permissioned third-party apps, mailboxes auto-forwarding to the outside, admin sprawl, "anyone with the link" sharing, spoofable email domains — and reports them as prioritised, self-resolving findings. Fix a problem and it clears itself on the next scan.

It runs on the [Sentinel](https://github.com/nizartuanku) engine: a single Go binary, no telemetry, offline licensing. It only ever reads, and it only ever reads the tenants you give it credentials for.

```
tenantwatch                       # dashboard on 127.0.0.1:8430
tenantwatch -creds tenants.json   # read-only credentials for your tenants
```

Add a tenant as `m365:contoso.onmicrosoft.com` or `gws:contoso.co.id`.

## What it checks

| Check | Severity | Catches |
|---|---|---|
| `tenant.admin-mfa` | High | Privileged accounts without MFA — the highest-value target |
| `tenant.user-mfa` | Medium | Standard accounts without MFA (aggregated coverage gap) |
| `tenant.legacy-auth` | High | Basic/legacy auth still enabled — bypasses MFA |
| `tenant.risky-oauth` | High/Med | Third-party apps granted broad mail/file access (org-wide consent = High) |
| `tenant.mail-forward` | High | Mailboxes auto-forwarding outside the org (BEC/exfil signal) |
| `tenant.admin-sprawl` | Medium | Too many standing administrator accounts |
| `tenant.external-sharing` | Medium | "Anyone with the link" / external file sharing |
| `tenant.email-auth` | Medium | Missing SPF / DKIM / weak DMARC (spoofable domain) |
| `tenant.no-conditional-access` | Medium | No enforced conditional-access policy (M365) |
| `tenant.inactive-user` | Low | Enabled accounts unused for 90+ days |

## Honest limits (v0)

TenantWatch tells you what it *couldn't* assess instead of pretending everything it didn't read is fine — those show up as `Manual review` info findings. In v0:

- **Microsoft 365**: sign-in-activity (inactive accounts) needs Entra ID P1; per-mailbox external forwarding needs an Exchange mailbox read — both are surfaced as manual-review notes unless the permissions are present.
- **Google Workspace**: OAuth token audit needs the Reports API; Drive external-sharing policy needs Drive settings; per-user IMAP/POP is a Gmail setting — surfaced as manual-review notes.
- Email authentication (SPF/DKIM/DMARC) is read from public DNS; DKIM is best-effort (selectors vary), so its absence is reported as "not detected", never as broken.
- Unlike the rest of the Sentinel line, TenantWatch needs outbound access to the Microsoft Graph / Google APIs (it reads *your* tenant, read-only). Credentials and findings stay on your server.

## Editions

| | Free (this repo) | Pro | Team |
|---|---|---|---|
| Tenants | 1 | 10 | unlimited |
| History | 30 days | 365 days | unlimited |
| Scan now / custom interval | — | ✓ | ✓ |
| Channels | webhook, syslog | + email, Slack, Telegram | + PagerDuty, Teams |

The free edition is Apache-2.0 and fully functional for one tenant. **Pro and Team** (licensed builds, offline activation): **[whop.com/tenantwatch](https://whop.com/tenantwatch)** — 14-day trial.

## Install

See [docs/INSTALL.md](docs/INSTALL.md) for the read-only app-registration (M365) and service-account (Google Workspace) setup, and [docs/USER-GUIDE.md](docs/USER-GUIDE.md) for day-to-day use. Quick start:

```sh
# from a release tarball
tar xzf tenantwatch-*-linux-amd64.tar.gz && cd tenantwatch-*
cp tenants.example.json tenants.json   # fill in your read-only credentials
./tenantwatch -creds tenants.json
# open http://127.0.0.1:8430
```

Findings can be pushed to any webhook or to a syslog collector — point `-syslog` at [Loglight](https://github.com/nizartuanku/loglight) to correlate a tenant posture change with what your logs saw.

## Part of the Sentinel line

Self-hosted security tools on one engine — TLS monitoring, attack-surface discovery, canary tokens, CVE prioritisation, firewall auditing, log correlation, DMARC, and this. See the full line and the **Sentinel Suite** bundle at **[whop.com/nizar-tuanku](https://whop.com/nizar-tuanku)**.

More from Nizar Tuanku: [YouTube](https://www.youtube.com/@nizartuanku7102) · [TikTok](https://www.tiktok.com/@nizartuanku) · Instagram [@nizartuanku]

## License

Apache-2.0 (free edition). See [LICENSE](LICENSE).
