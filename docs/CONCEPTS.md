# TenantWatch — Concepts

What this product is, what problem it solves, and why it works the way it does — written for
someone meeting the problem for the first time. The command reference is in the README; this
is the reasoning behind it.

*Hexward Labs · Nizar Tuanku — Cybersecurity. · last reviewed 12 September 2026*

---

## The company has no servers left, and nobody audits what replaced them

A small company that once had a file server, a mail server and a firewall now has a Microsoft 365
or Google Workspace tenant and a wifi router. The servers went away, and so did the reflex to check
them. Nobody runs a monthly review of a cloud tenant, because there is no box to walk up to and
nothing that visibly needs patching.

Meanwhile the tenant quietly became the entire company. It holds the mail, the documents, the
identities and the ability to reset any of them. An attacker who signs in as one finance user does
not need to breach a network; they are already inside everything that matters.

The settings that decide whether that is easy or hard are spread across a dozen admin pages, each
with its own defaults, most of which were never revisited after the migration weekend.

## Two different questions, and only one of them is usually asked

There is a question about **configuration**: is multi-factor authentication required, is legacy
authentication switched off, can a mailbox forward itself to an outside address, how many people
hold administrator rights, can a document be shared with "anyone with the link", is the domain
spoofable because SPF or DMARC is missing?

And there is a question about **what actually happened**: did anyone sign in through a legacy
protocol last week, did an administrator complete a sign-in with a password alone, did one address
fail against forty accounts and then succeed against one, did an account appear in two countries
four hours apart?

Configuration tells you the door is unlocked. The sign-in log tells you somebody walked through it.
Almost every posture tool answers only the first question, and it is the weaker of the two: a
policy that permits something is a risk, a log entry proving it happened is an incident. TenantWatch
answers both, and grades them differently on purpose — `tenant.legacy-auth` is High because the
door is open, `tenant.signin-legacy-auth` is Critical because the log says it was used.

## Findings that clear themselves

Every check produces findings that are recomputed from scratch on the next scan. Fix the problem —
enable MFA on the admin account, remove the forwarding rule — and the finding disappears by itself.
Nothing has to be ticked off, and nothing can be marked resolved while remaining true.

That sounds like a small design choice and it is the difference between a report and a control. A
report is a photograph of one afternoon; a list that maintains itself is a description of the
tenant as it is now.

## No baseline, no learning period

The sign-in checks read the last seven days each time they run and judge that window as a whole.
There is no stored profile of "normal", no training period, and no first-week grace during which the
product is quietly useless.

This is a deliberate trade. A learned baseline can spot subtler anomalies, but it also inherits
whatever was already happening while it learned: if the spray was running during training, the spray
becomes normal. Pure functions over a fixed window cannot be poisoned that way, and the first scan is
worth exactly as much as the hundredth — which matters for a product a small company installs on a
Friday because something felt wrong.

## What it refuses to pretend

The honest-limits problem in tenant auditing is specific and severe: much of what you would want to
check sits behind a licence tier or an API permission, and a tool that cannot read something can
either say so or quietly report nothing — which looks identical to "all clear".

Two examples, both stated in the product rather than buried in a FAQ.

Microsoft gates the sign-in log behind Entra ID P1 or P2. P1 ships with Microsoft 365 Business
Premium but not with Business Basic or Business Standard, so on a large share of small-business
tenants the sign-in checks cannot run at all. TenantWatch names the licence and the plan that
includes it, in the dashboard, instead of showing an empty section.

On Google Workspace the login audit publishes no country per event and no per-event authentication
strength, so the country-hop and admin-single-factor checks cannot run there — not because they were
not written, but because the data does not exist. They are reported as unassessed. In exchange
Google publishes its own suspicious-login verdict, which is surfaced as its own finding.

The same applies to permissions the tenant has not granted: per-mailbox forwarding on Microsoft 365,
the OAuth token audit and Drive sharing policy on Google Workspace. Each becomes a *manual review*
note naming what was not read. A tenant that cannot be assessed is told so. It never gets a clean
bill of health it did not earn.

## Read-only, and honest about the one connection it makes

TenantWatch authenticates with read-only credentials you create — an app registration on Microsoft
365, a service account on Google Workspace — and it never writes. It cannot disable an account,
change a policy or send mail, because it was never granted the ability to.

Unlike the rest of the Hexward line, it is not fully offline: reading your tenant means calling
Microsoft Graph or the Google APIs. That is the one outbound connection it makes, it goes to your
provider and nowhere else, and both the credentials and the findings stay on your own server. There
is no vendor cloud in the middle holding a copy of your tenant's weaknesses, and no telemetry.
Licence activation is offline cryptography, so even paying customers never phone home.

## What changes once you are using it

Before: the tenant's security settings are whatever the migration consultant left behind, and nobody
would notice a forwarding rule added to the finance mailbox for six months.

After: one page lists what is wrong, worst first, in the words a non-specialist can act on; what
could not be checked and why; and — where the licence allows it — the sign-ins from the past week
that suggest a door has already been used.

## Try it on one tenant

```
curl -LO https://github.com/nizartuanku/tenantwatch/releases/latest/download/tenantwatch-free-0.2.0-linux-amd64.tar.gz
curl -LO https://github.com/nizartuanku/tenantwatch/releases/latest/download/SHA256SUMS
grep 'tenantwatch-free-0.2.0-linux-amd64.tar.gz' SHA256SUMS | sha256sum -c -
tar xzf tenantwatch-free-0.2.0-linux-amd64.tar.gz && cd tenantwatch-0.2.0
cp tenants.example.json tenants.json
./tenantwatch -creds tenants.json
```

`SHA256SUMS` covers both archives attached to the release, so the `grep` form checks the one file you
downloaded. The dashboard is on `http://127.0.0.1:8430`. A tenant is added as
`m365:contoso.onmicrosoft.com` or `gws:contoso.co.id`; `docs/INSTALL.md` walks through creating the
read-only app registration or service account, which is the only genuinely fiddly part.

The free Apache-2.0 edition audits one tenant with every check enabled and no time limit. Pro and
Team are paid licences on Whop —
[whop.com/nizar-tuanku/tenantwatch](https://whop.com/nizar-tuanku/tenantwatch?utm_source=github);
nothing on Whop is free, so try it here first.

Nizar Tuanku — Cybersecurity. · github.com/nizartuanku/tenantwatch

## Terms used above

- Tenant — one organisation's own space inside Microsoft 365 or Google Workspace: its users, mailboxes, files and settings.
- Legacy authentication — older mail protocols such as IMAP, POP and SMTP that send a password and cannot carry a second factor.
- Conditional access — a policy that decides whether a sign-in is allowed based on who, from where, and on what device.
- Password spray — trying one or two common passwords against many accounts, which stays under the lockout threshold of each one.
- SPF, DKIM, DMARC — public DNS records that let a receiving mail server tell whether a message claiming to be from your domain really is.
