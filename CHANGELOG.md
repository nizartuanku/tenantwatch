# Changelog

## 0.2.2 — 2026-09-24

- **AI Assist (optional): an ✨ Explain button on every finding.** When TenantWatch is started
  with `-ai-assist-url`, a local [hexward-ai](https://github.com/nizartuanku/hexward-ai) sidecar
  explains a finding in plain language and lists what to verify. The engine remains the only
  source of findings and severity. Only one sanitised finding is sent (secret-like evidence keys
  are dropped). Any AI failure shows a quiet note and changes nothing. Free edition: a sidecar on
  the same host. Pro/Team: also a dedicated AI host or your own endpoint
  (`-ai-assist-key-file`). English or Bahasa Indonesia (`-ai-assist-lang`). New endpoints
  `GET /api/ai` and `POST /api/findings/explain`, covered by tests for: AI off, bad config,
  sanitising, tier gating, sidecar down, and bad requests.

## 0.2.1 — 2026-09-23

- **Slack and Telegram alerts, and an honest edition boundary.** Both channels are wired to real flags (`-slack-webhook`, `-telegram-token` / `-telegram-chat`) and are Pro and Team features. The free edition does not silently drop them and does not pretend to send: it refuses the flag at startup, names the edition that carries the channel, and links the product page. Webhook and syslog remain available in every edition. The flags are documented in the user guide next to the channels that were already there.
- **`scripts/first-run.sh` — one command from a clean machine to a working dashboard.** It resolves the latest release at run time rather than pinning a tag, verifies the download against `SHA256SUMS` with no `--ignore-missing`, extracts, starts the binary and polls the dashboard until it answers. If the port is already taken it says so instead of letting the binary exit a second later and read like a broken product (`FIRST_RUN_PORT` overrides). Step 1 uses the unauthenticated GitHub API, which allows 60 calls per hour per address; when that runs out the script now names the rate limit instead of reporting "cannot reach".
- **Verification identifiers renamed to Hexward.** The HTTP header, DNS TXT label and well-known file used to prove ownership now read `X-Hexward-Token`, `_hexward-verify.<domain>` and `/.well-known/hexward-verify.txt`. A challenge is satisfied by either the old or the new identifier and the webhook sends both headers, so nothing already installed breaks. The old names are removed on **1 March 2027**.
- **The product page is reachable from inside the product.** The messages that report a free-edition limit, and the dashboard footer, now say where the paid editions are — a product URL, not a plan id.
- **`docs/CONCEPTS.md`** — configuration says the door is unlocked; the sign-in log says it was used. What TenantWatch reads, and why the two answers differ.
- The release archive is named `tenantwatch-free-<version>-linux-amd64.tar.gz`, matching the other free builds, and the README install block follows the order that was actually tested: verify the checksum, extract, `cd`, run.
- The README states the pricing rule plainly: Whop sells paid licences only; the free build is downloaded here.
- Packaging: the `LICENSE` / `license` collision is fixed and the real licence text ships with the source; one copyright holder is named.
- CI runs `gofmt`, `go vet` and `go test` on every push.

## 0.2.0 — 2026-08-25

Configuration checks say the door is unlocked; the sign-in log says somebody walked through it. 0.2.0 reads the last 7 days of sign-in activity and turns it into findings: a legacy protocol that succeeded, an administrator completing a sign-in with a password alone, a spray that eventually landed, one account in two countries too close together to be travel, and sign-ins the provider itself flagged.

## 0.1.0 — 2026-08-23

First tagged release. Read-only Microsoft 365 and Google Workspace posture auditing: MFA gaps, legacy auth, risky third-party OAuth apps, external auto-forwarding, admin sprawl, "anyone with the link" sharing, missing or weak SPF/DKIM/DMARC, missing conditional access, inactive accounts. Dashboard on `http://127.0.0.1:8430`.
