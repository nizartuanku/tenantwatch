package tenant

import (
	"testing"
	"time"

	"github.com/nizartuanku/tenantwatch/core"
)

// richState triggers every check at least once, so one Evaluate exercises the
// whole engine.
func richState() TenantState {
	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	users := []User{
		{Email: "ceo@contoso.co.id", Enabled: true, IsAdmin: true, AdminRoles: []string{"Global Administrator"}, MFAEnabled: false},
		{Email: "it1@contoso.co.id", Enabled: true, IsAdmin: true, AdminRoles: []string{"Global Administrator"}, MFAEnabled: true},
		{Email: "it2@contoso.co.id", Enabled: true, IsAdmin: true, MFAEnabled: true},
		{Email: "it3@contoso.co.id", Enabled: true, IsAdmin: true, MFAEnabled: true},
		{Email: "it4@contoso.co.id", Enabled: true, IsAdmin: true, MFAEnabled: true},
		{Email: "it5@contoso.co.id", Enabled: true, IsAdmin: true, MFAEnabled: true},
		{Email: "u1@contoso.co.id", Enabled: true, MFAEnabled: false},
		{Email: "u2@contoso.co.id", Enabled: true, MFAEnabled: true},
		{Email: "old@contoso.co.id", Enabled: true, MFAEnabled: true, LastActive: now.AddDate(0, 0, -200)},
		{Email: "sales@contoso.co.id", Enabled: true, MFAEnabled: true, ExternalForwarding: true, ForwardTarget: "attacker@evil.test"},
	}
	return TenantState{
		Provider: ProviderM365, Domain: "contoso.co.id", TakenAt: now,
		Users:             users,
		LegacyAuthEnabled: true,
		ConditionalAccess: false,
		Grants: []OAuthGrant{
			{AppID: "app-1", AppName: "MailBot", Scopes: []string{"Mail.ReadWrite"}, ConsentType: "AllPrincipals"},
			{AppID: "app-2", AppName: "Harmless", Scopes: []string{"User.Read"}, ConsentType: "Principal"},
		},
		Sharing: SharingConfig{AnyoneLinks: true, Level: "ExternalUserAndGuestSharing"},
		Domains: []DomainAuth{{Domain: "contoso.co.id", SPF: true, DKIM: false, DMARCPolicy: "none"}},
		Notes:   []string{"something unassessed"},
		Assessed: map[string]bool{
			AreaMFA: true, AreaAdminRoles: true, AreaLegacyAuth: true, AreaOAuth: true,
			AreaSharing: true, AreaEmailAuth: true, AreaConditional: true, AreaInactiveUser: true,
			AreaMailForward: true,
		},
	}
}

func bySeverity(fs []core.Finding) map[string]core.Severity {
	m := map[string]core.Severity{}
	for _, f := range fs {
		// keep the most severe per check
		if cur, ok := m[f.Check]; !ok || f.Severity != cur {
			m[f.Check] = f.Severity
		}
	}
	return m
}

func TestEvaluateFiresEveryCheck(t *testing.T) {
	fs := Evaluate(richState())
	got := bySeverity(fs)

	want := map[string]core.Severity{
		"tenant.admin-mfa":             core.SeverityHigh,
		"tenant.user-mfa":              core.SeverityMedium,
		"tenant.legacy-auth":           core.SeverityHigh,
		"tenant.risky-oauth":           core.SeverityHigh, // AllPrincipals consent
		"tenant.admin-sprawl":          core.SeverityMedium,
		"tenant.mail-forward":          core.SeverityHigh,
		"tenant.external-sharing":      core.SeverityMedium,
		"tenant.email-auth":            core.SeverityMedium,
		"tenant.no-conditional-access": core.SeverityMedium,
		"tenant.inactive-user":         core.SeverityLow,
		"tenant.manual-review":         core.SeverityInfo,
	}
	for check, sev := range want {
		if got[check] != sev {
			t.Errorf("%s: got %q, want %q", check, got[check], sev)
		}
	}
	// Every finding must carry remediation (core contract).
	for _, f := range fs {
		if err := f.ValidateForIngest(); err != nil {
			t.Errorf("finding %q invalid: %v", f.Check, err)
		}
	}
}

func TestHarmlessOAuthNotFlagged(t *testing.T) {
	s := richState()
	// Only the harmless grant.
	s.Grants = []OAuthGrant{{AppID: "x", AppName: "Harmless", Scopes: []string{"User.Read", "openid"}, ConsentType: "Principal"}}
	for _, f := range Evaluate(s) {
		if f.Check == "tenant.risky-oauth" {
			t.Fatalf("harmless grant should not fire risky-oauth: %s", f.Title)
		}
	}
}

func TestUnassessedAreaStaysSilent(t *testing.T) {
	s := richState()
	// Provider could not read MFA — the MFA checks must not fire (no false alarm).
	s.Assessed[AreaMFA] = false
	for _, f := range Evaluate(s) {
		if f.Check == "tenant.admin-mfa" || f.Check == "tenant.user-mfa" {
			t.Fatalf("MFA check fired for an unassessed area: %s", f.Check)
		}
	}
}

func TestGWSNoConditionalAccessFinding(t *testing.T) {
	s := richState()
	s.Provider = ProviderGWS // conditional access is M365-only; must not fire for GWS
	for _, f := range Evaluate(s) {
		if f.Check == "tenant.no-conditional-access" {
			t.Fatalf("conditional-access finding must not fire for Google Workspace")
		}
	}
}

func TestDMARCRejectClears(t *testing.T) {
	s := richState()
	s.Domains = []DomainAuth{{Domain: "contoso.co.id", SPF: true, DKIM: true, DMARCPolicy: "reject"}}
	for _, f := range Evaluate(s) {
		if f.Check == "tenant.email-auth" {
			t.Fatalf("a fully-configured domain should not fire email-auth: %s", f.Title)
		}
	}
}
