package tenant

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nizartuanku/tenantwatch/core"
)

// ModuleID is the module id used across findings and the scheduler.
const ModuleID = "tenantwatch"

// InactiveDays is how long an enabled account may sit unused before it is
// flagged as an unnecessary attack surface.
const InactiveDays = 90

// AdminSprawlThreshold is the count of privileged admins above which the tenant
// is flagged for over-provisioned administration (CIS/Microsoft guidance:
// keep global admins to a small handful).
const AdminSprawlThreshold = 5

// Evaluate is the whole product's judgement: a pure function from a posture
// snapshot to prioritised findings. Deterministic, side-effect free, and
// exhaustively testable. The reconcile engine turns the returned findings into
// open/resolved lifecycle for free — fix the MFA gap and next scan the finding
// simply stops being returned, so it auto-resolves.
func Evaluate(s TenantState) []core.Finding {
	target := Canonical(s.Provider, s.Domain)
	var out []core.Finding

	out = append(out, checkAdminMFA(target, s)...)
	out = append(out, checkUserMFA(target, s)...)
	out = append(out, checkLegacyAuth(target, s)...)
	out = append(out, checkOAuth(target, s)...)
	out = append(out, checkAdminSprawl(target, s)...)
	out = append(out, checkMailForward(target, s)...)
	out = append(out, checkSharing(target, s)...)
	out = append(out, checkEmailAuth(target, s)...)
	out = append(out, checkConditionalAccess(target, s)...)
	out = append(out, checkInactiveUsers(target, s)...)
	out = append(out, checkSignIns(target, s)...)
	out = append(out, notesToFindings(target, s)...)

	return out
}

// checkAdminMFA — every privileged account without MFA is its own High finding
// (one per admin, so fixing one resolves only that one).
func checkAdminMFA(target string, s TenantState) []core.Finding {
	if !s.Assessed[AreaMFA] || !s.Assessed[AreaAdminRoles] {
		return nil
	}
	var out []core.Finding
	for _, u := range s.Users {
		if !u.Enabled || !u.IsAdmin || u.MFAEnabled {
			continue
		}
		out = append(out, core.Finding{
			Fingerprint: core.Fingerprint(ModuleID, target, "tenant.admin-mfa", strings.ToLower(u.Email)),
			Target:      target,
			Check:       "tenant.admin-mfa",
			Title:       "Admin without MFA: " + u.Email + " (" + strings.Join(u.AdminRoles, ", ") + ")",
			Severity:    core.SeverityHigh,
			Remediation: "Require MFA for " + u.Email + " immediately. A privileged account without a second factor is the single highest-value target in the tenant.",
			Evidence: map[string]any{
				"user": u.Email, "roles": u.AdminRoles, "provider": s.Provider,
			},
		})
	}
	return out
}

// checkUserMFA — regular accounts are aggregated: one Medium finding carrying
// the coverage gap, so the dashboard shows "12 of 90 users lack MFA" rather
// than 12 separate rows. The fingerprint has no changing discriminator, so the
// finding is stable and its title updates as the count moves.
func checkUserMFA(target string, s TenantState) []core.Finding {
	if !s.Assessed[AreaMFA] {
		return nil
	}
	var missing []string
	total := 0
	for _, u := range s.Users {
		if !u.Enabled || u.IsAdmin {
			continue
		}
		total++
		if !u.MFAEnabled {
			missing = append(missing, u.Email)
		}
	}
	if len(missing) == 0 || total == 0 {
		return nil
	}
	sort.Strings(missing)
	preview := missing
	if len(preview) > 10 {
		preview = preview[:10]
	}
	return []core.Finding{{
		Fingerprint: core.Fingerprint(ModuleID, target, "tenant.user-mfa", ""),
		Target:      target,
		Check:       "tenant.user-mfa",
		Title:       fmt.Sprintf("%d of %d standard users have no MFA", len(missing), total),
		Severity:    core.SeverityMedium,
		Remediation: "Enforce MFA org-wide via a security-defaults or conditional-access policy. Password-only accounts are the primary entry point for account takeover.",
		Evidence: map[string]any{
			"missing_count": len(missing), "user_total": total, "sample": preview, "provider": s.Provider,
		},
	}}
}

func checkLegacyAuth(target string, s TenantState) []core.Finding {
	if !s.Assessed[AreaLegacyAuth] || !s.LegacyAuthEnabled {
		return nil
	}
	return []core.Finding{{
		Fingerprint: core.Fingerprint(ModuleID, target, "tenant.legacy-auth", ""),
		Target:      target,
		Check:       "tenant.legacy-auth",
		Title:       "Legacy authentication is still enabled",
		Severity:    core.SeverityHigh,
		Remediation: "Block legacy authentication (IMAP/POP/SMTP basic auth). Legacy protocols bypass MFA entirely and are the vector for most password-spray success.",
		Evidence:    map[string]any{"provider": s.Provider},
	}}
}

func checkOAuth(target string, s TenantState) []core.Finding {
	if !s.Assessed[AreaOAuth] {
		return nil
	}
	var out []core.Finding
	for _, g := range s.Grants {
		risky := riskyScopes(g.Scopes)
		if len(risky) == 0 {
			continue
		}
		sev := core.SeverityMedium
		// Org-wide (admin-consented) grants of broad mail/file access are the
		// dangerous ones — one consent exposes every mailbox.
		if strings.EqualFold(g.ConsentType, "AllPrincipals") {
			sev = core.SeverityHigh
		}
		pub := g.Publisher
		if pub == "" {
			pub = "unverified publisher"
		}
		out = append(out, core.Finding{
			Fingerprint: core.Fingerprint(ModuleID, target, "tenant.risky-oauth", strings.ToLower(g.AppID)),
			Target:      target,
			Check:       "tenant.risky-oauth",
			Title:       "Third-party app with broad access: " + appLabel(g) + " (" + pub + ")",
			Severity:    sev,
			Remediation: "Review and, if not clearly needed, revoke consent for " + appLabel(g) + ". It can read/write mail or files across the accounts that granted it.",
			Evidence: map[string]any{
				"app": appLabel(g), "app_id": g.AppID, "consent": g.ConsentType,
				"risky_scopes": risky, "publisher": g.Publisher, "provider": s.Provider,
			},
		})
	}
	return out
}

func checkAdminSprawl(target string, s TenantState) []core.Finding {
	if !s.Assessed[AreaAdminRoles] {
		return nil
	}
	admins := 0
	for _, u := range s.Users {
		if u.Enabled && u.IsAdmin {
			admins++
		}
	}
	if admins <= AdminSprawlThreshold {
		return nil
	}
	return []core.Finding{{
		Fingerprint: core.Fingerprint(ModuleID, target, "tenant.admin-sprawl", ""),
		Target:      target,
		Check:       "tenant.admin-sprawl",
		Title:       fmt.Sprintf("%d accounts hold administrator roles", admins),
		Severity:    core.SeverityMedium,
		Remediation: "Reduce standing admin access to the minimum, and prefer just-in-time elevation. Every admin account is an equally valuable target; fewer is safer.",
		Evidence:    map[string]any{"admin_count": admins, "threshold": AdminSprawlThreshold, "provider": s.Provider},
	}}
}

func checkMailForward(target string, s TenantState) []core.Finding {
	if !s.Assessed[AreaMailForward] {
		return nil
	}
	var out []core.Finding
	for _, u := range s.Users {
		if !u.ExternalForwarding {
			continue
		}
		out = append(out, core.Finding{
			Fingerprint: core.Fingerprint(ModuleID, target, "tenant.mail-forward", strings.ToLower(u.Email)),
			Target:      target,
			Check:       "tenant.mail-forward",
			Title:       "Mailbox auto-forwards outside the org: " + u.Email + " → " + u.ForwardTarget,
			Severity:    core.SeverityHigh,
			Remediation: "Verify this forward with " + u.Email + " and remove it if unexpected. External auto-forwarding is a hallmark of a compromised mailbox (BEC/exfiltration).",
			Evidence:    map[string]any{"user": u.Email, "forward_to": u.ForwardTarget, "provider": s.Provider},
		})
	}
	return out
}

func checkSharing(target string, s TenantState) []core.Finding {
	if !s.Assessed[AreaSharing] {
		return nil
	}
	if !s.Sharing.AnyoneLinks && !s.Sharing.ExternalSharing {
		return nil
	}
	sev := core.SeverityMedium
	title := "External file sharing is enabled"
	rem := "Restrict external sharing to specific, authenticated guests only if the business needs it."
	if s.Sharing.AnyoneLinks {
		title = "\"Anyone with the link\" file sharing is enabled"
		rem = "Disable anonymous \"anyone with the link\" sharing. Such links need no sign-in and are frequently indexed or leaked, exposing whatever they point to."
	}
	return []core.Finding{{
		Fingerprint: core.Fingerprint(ModuleID, target, "tenant.external-sharing", ""),
		Target:      target,
		Check:       "tenant.external-sharing",
		Title:       title,
		Severity:    sev,
		Remediation: rem,
		Evidence:    map[string]any{"anyone_links": s.Sharing.AnyoneLinks, "external": s.Sharing.ExternalSharing, "level": s.Sharing.Level, "provider": s.Provider},
	}}
}

func checkEmailAuth(target string, s TenantState) []core.Finding {
	if !s.Assessed[AreaEmailAuth] {
		return nil
	}
	var out []core.Finding
	for _, d := range s.Domains {
		var problems []string
		sev := core.SeverityLow
		switch d.DMARCPolicy {
		case "":
			problems = append(problems, "no DMARC record")
			sev = core.SeverityMedium
		case "none":
			problems = append(problems, "DMARC p=none (monitoring only — spoofable)")
			sev = core.SeverityMedium
		}
		if !d.SPF {
			problems = append(problems, "no SPF record")
			if sev == core.SeverityLow {
				sev = core.SeverityMedium
			}
		}
		// DKIM absence alone is not flagged (selectors vary and can't be
		// reliably enumerated); it's added as context only when SPF/DMARC
		// already put the domain in a firing state.
		if len(problems) == 0 {
			continue
		}
		if !d.DKIM {
			problems = append(problems, "DKIM not detected")
		}
		out = append(out, core.Finding{
			Fingerprint: core.Fingerprint(ModuleID, target, "tenant.email-auth", strings.ToLower(d.Domain)),
			Target:      target,
			Check:       "tenant.email-auth",
			Title:       "Email spoofing risk on " + d.Domain + ": " + strings.Join(problems, ", "),
			Severity:    sev,
			Remediation: "Publish SPF and DKIM, then raise DMARC from none → quarantine → reject once your reports are clean. Until then, anyone can send mail as @" + d.Domain + ".",
			Evidence:    map[string]any{"domain": d.Domain, "spf": d.SPF, "dkim": d.DKIM, "dmarc": d.DMARCPolicy, "provider": s.Provider},
		})
	}
	return out
}

func checkConditionalAccess(target string, s TenantState) []core.Finding {
	// Only meaningful for M365; Google's equivalent (context-aware access) is a
	// premium add-on, so a missing one there is not a finding.
	if !s.Assessed[AreaConditional] || s.Provider != ProviderM365 || s.ConditionalAccess {
		return nil
	}
	return []core.Finding{{
		Fingerprint: core.Fingerprint(ModuleID, target, "tenant.no-conditional-access", ""),
		Target:      target,
		Check:       "tenant.no-conditional-access",
		Title:       "No enforced conditional-access policy",
		Severity:    core.SeverityMedium,
		Remediation: "Add at least a baseline conditional-access policy (require MFA for admins, block legacy auth). Without one, sign-ins are governed only by password + optional MFA.",
		Evidence:    map[string]any{"provider": s.Provider},
	}}
}

func checkInactiveUsers(target string, s TenantState) []core.Finding {
	if !s.Assessed[AreaInactiveUser] {
		return nil
	}
	cutoff := s.TakenAt
	if cutoff.IsZero() {
		return nil // without a snapshot time, "inactive" is unknowable — stay silent
	}
	cutoff = cutoff.AddDate(0, 0, -InactiveDays)
	var stale []string
	for _, u := range s.Users {
		if !u.Enabled || u.LastActive.IsZero() {
			continue
		}
		if u.LastActive.Before(cutoff) {
			stale = append(stale, u.Email)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	sort.Strings(stale)
	preview := stale
	if len(preview) > 10 {
		preview = preview[:10]
	}
	return []core.Finding{{
		Fingerprint: core.Fingerprint(ModuleID, target, "tenant.inactive-user", ""),
		Target:      target,
		Check:       "tenant.inactive-user",
		Title:       fmt.Sprintf("%d enabled account(s) unused for over %d days", len(stale), InactiveDays),
		Severity:    core.SeverityLow,
		Remediation: "Disable or remove accounts that are no longer used. Dormant enabled accounts widen the attack surface with no benefit.",
		Evidence:    map[string]any{"count": len(stale), "days": InactiveDays, "sample": preview, "provider": s.Provider},
	}}
}

// notesToFindings surfaces the provider's honest "could not assess" notes as
// Info findings, so the user sees the tool's blind spots instead of mistaking
// silence for a clean bill of health.
func notesToFindings(target string, s TenantState) []core.Finding {
	var out []core.Finding
	for _, n := range s.Notes {
		out = append(out, core.Finding{
			Fingerprint: core.Fingerprint(ModuleID, target, "tenant.manual-review", n),
			Target:      target,
			Check:       "tenant.manual-review",
			Title:       "Manual review: " + n,
			Severity:    core.SeverityInfo,
			Remediation: "Review this area manually — TenantWatch could not assess it automatically with the permissions granted.",
			Evidence:    map[string]any{"provider": s.Provider},
		})
	}
	return out
}

// --- helpers ----------------------------------------------------------------

func riskyScopes(scopes []string) []string {
	var out []string
	for _, sc := range scopes {
		low := strings.ToLower(sc)
		for _, r := range riskyOAuthScopes {
			if strings.Contains(low, r) {
				out = append(out, sc)
				break
			}
		}
	}
	return out
}

func appLabel(g OAuthGrant) string {
	if g.AppName != "" {
		return g.AppName
	}
	return g.AppID
}

// Canonical builds the scan target key "provider:domain".
func Canonical(provider, domain string) string {
	return strings.ToLower(provider) + ":" + strings.ToLower(domain)
}

// SplitCanonical parses "provider:domain" back into parts.
func SplitCanonical(canonical string) (provider, domain string, ok bool) {
	parts := strings.SplitN(canonical, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
