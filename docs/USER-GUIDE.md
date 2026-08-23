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

## Manual-review notes

Info findings labelled **Manual review** are areas TenantWatch could not assess automatically with the permissions granted (for example, M365 sign-in activity without Entra ID P1). They are shown so you know the blind spot exists — silence is never mistaken for "all clear".

## Alerts

- `-webhook https://…` posts a structured JSON digest on new/resolved findings.
- `-syslog host:5514` emits one syslog line per finding. Point it at [Loglight](https://github.com/nizartuanku/loglight) to correlate a posture change with live log activity.
- Email / Slack / Telegram / PagerDuty / Teams are Pro/Team channels.

## Tiers

Free = 1 tenant, 30-day history, webhook + syslog. Pro = 10 tenants, 365-day history, scan-now, custom interval, chat channels. Team = unlimited. Paste a license key in the dashboard (or drop it next to the binary) — activation is fully offline.
