# TenantWatch — User Guide

## The dashboard

- **Posture** tiles show open findings by severity (Critical → Info).
- **Tenants** — add each workspace as `m365:<domain>` or `gws:<domain>`. The free edition covers one tenant; Pro covers ten; Team is unlimited.
- **Findings** — every open issue, most severe first, each with a one-line **what to do**. Findings are self-resolving: fix the underlying setting and the finding clears on the next scan (it does not linger as history).

## How findings work

TenantWatch takes a read-only snapshot of the tenant every 12 hours and evaluates it. A finding stays **open** while the problem is present and auto-**resolves** after two consecutive clean scans (so a brief API hiccup never flaps it). Nothing is ever changed in your tenant — TenantWatch only reads.

## Reading a finding

Each finding carries: severity, the affected tenant, a plain-language title, and a remediation step. Examples:

- **Admin without MFA** (High) — a privileged account with no second factor. Fix first.
- **Third-party app with broad access** (High when org-wide) — an app that can read/write mail or files across accounts. Review and revoke if it isn't clearly needed.
- **Mailbox auto-forwards outside the org** (High) — often the first sign of a compromised mailbox. Verify with the user.
- **Email spoofing risk** (Medium) — SPF/DKIM/DMARC gaps let anyone send mail as your domain. Raise DMARC `none → quarantine → reject`.

## Sign-in Watch

Configuration findings tell you a door is unlocked. **Sign-in findings tell you somebody walked through it** — so they outrank their configuration equivalents, and they are the ones to act on today.

Each scan reads the last **7 days** of sign-in activity. There is no stored baseline and no learning period: the first scan is as useful as the hundredth.

- **Legacy authentication succeeded** (Critical) — an IMAP/POP/SMTP client actually signed in. Legacy protocols cannot carry MFA, so that account is password-only in practice. Compare with `tenant.legacy-auth` (High), which only says the protocol is *permitted*.
- **Admin signed in without MFA** (Critical) — an administrator completed a real sign-in with a password alone. Not a policy gap on paper; it already happened.
- **Password spray succeeded** (Critical) — many failures across many accounts from one address, **and then one success**. Treat the account that succeeded as compromised: reset the password, revoke sessions, and check the mailbox for forwarding rules before anything else.
- **Sign-ins from two countries too close together** (High) — one account, two countries, a gap too short to be travel. A VPN or a corporate egress abroad explains it innocently, so both sign-ins are shown and you judge.
- **Provider flagged the sign-in as suspicious** (High) — Google's own verdict, surfaced rather than second-guessed.

**Where it cannot run, it says so.** On Microsoft 365 the sign-in log needs Entra ID P1 or P2 (included in Business Premium, not in Business Basic or Standard) *and* the `AuditLog.Read.All` permission; a missing licence and a missing permission produce two different, clearly named notes. On Google Workspace there is no licence gate, but Google reports no country and no per-event authentication strength, so the two-country and admin-MFA sign-in checks stay silent there. See [INSTALL.md](INSTALL.md).

## Manual-review notes

Info findings labelled **Manual review** are areas TenantWatch could not assess automatically with the permissions granted (for example, the M365 sign-in log without Entra ID P1, or per-mailbox forwarding without an Exchange mailbox read). They are shown so you know the blind spot exists — silence is never mistaken for "all clear".

## Alerts

- `-webhook https://…` posts a structured JSON digest on new/resolved findings.
- `-syslog host:5514` emits one syslog line per finding. Point it at [Loglight](https://github.com/nizartuanku/loglight) to correlate a posture change with live log activity.
- Email / Slack / Telegram / PagerDuty / Teams are Pro/Team channels.

## Tiers

Free = 1 tenant, 30-day history, webhook + syslog. Pro = 10 tenants, 365-day history, scan-now, custom interval, chat channels. Team = unlimited. Paste a license key in the dashboard (or drop it next to the binary) — activation is fully offline.
