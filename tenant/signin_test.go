package tenant

import (
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/tenantwatch/core"
)

var base = time.Date(2026, 8, 20, 9, 0, 0, 0, time.UTC)

// signInState builds a snapshot that has read the sign-in log, so the checks
// are live. Areas not named here stay unassessed on purpose.
func signInState(events []SignIn, users ...User) TenantState {
	return TenantState{
		Provider: ProviderM365,
		Domain:   "contoso.example",
		TakenAt:  base,
		Users:    users,
		SignIns:  events,
		Assessed: map[string]bool{AreaSignIn: true, AreaAdminRoles: true},
	}
}

func checks(t *testing.T, s TenantState, check string) []core.Finding {
	t.Helper()
	var out []core.Finding
	for _, f := range Evaluate(s) {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

// The single most important property of the whole feature: a log that was never
// read must never look like a clean one.
func TestUnassessedSignInLogProducesNothing(t *testing.T) {
	s := signInState([]SignIn{
		{UserEmail: "a@contoso.example", At: base, Success: true, LegacyAuth: true, ClientApp: "IMAP4"},
	})
	s.Assessed[AreaSignIn] = false

	for _, f := range Evaluate(s) {
		if strings.HasPrefix(f.Check, "tenant.signin") {
			t.Fatalf("an unread sign-in log produced a finding: %s", f.Check)
		}
	}
}

// --- 1. legacy auth that succeeded ------------------------------------------

func TestLegacyAuthSuccess(t *testing.T) {
	s := signInState([]SignIn{
		// Same client polling — must aggregate into ONE finding, not three.
		{UserEmail: "sales@contoso.example", At: base, Success: true, LegacyAuth: true, ClientApp: "IMAP4", Country: "VN"},
		{UserEmail: "sales@contoso.example", At: base.Add(5 * time.Minute), Success: true, LegacyAuth: true, ClientApp: "IMAP4", Country: "VN"},
		{UserEmail: "sales@contoso.example", At: base.Add(10 * time.Minute), Success: true, LegacyAuth: true, ClientApp: "IMAP4", Country: "VN"},
		// A legacy attempt that FAILED is not proof the door is usable.
		{UserEmail: "other@contoso.example", At: base, Success: false, LegacyAuth: true, ClientApp: "POP3"},
		// Modern auth is not this check's business.
		{UserEmail: "ok@contoso.example", At: base, Success: true, ClientApp: "Browser"},
	})

	got := checks(t, s, "tenant.signin-legacy-auth")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	if got[0].Severity != core.SeverityCritical {
		t.Errorf("severity = %s, want critical", got[0].Severity)
	}
	if !strings.Contains(got[0].Title, "sales@contoso.example") || !strings.Contains(got[0].Title, "IMAP4") {
		t.Errorf("title = %q", got[0].Title)
	}
	if !strings.Contains(got[0].Title, "3 sign-ins") {
		t.Errorf("count not aggregated into the title: %q", got[0].Title)
	}
	if !strings.Contains(got[0].Title, "VN") {
		t.Errorf("country missing from title: %q", got[0].Title)
	}
}

// --- 2. admin signed in with one factor -------------------------------------

func TestAdminSingleFactor(t *testing.T) {
	admin := User{Email: "boss@contoso.example", Enabled: true, IsAdmin: true, AdminRoles: []string{"Global Administrator"}}
	staff := User{Email: "staff@contoso.example", Enabled: true}

	s := signInState([]SignIn{
		{UserEmail: "boss@contoso.example", At: base, Success: true, SingleFactor: true},
		{UserEmail: "boss@contoso.example", At: base.Add(time.Hour), Success: true, SingleFactor: true},
		// Not an admin → not this finding.
		{UserEmail: "staff@contoso.example", At: base, Success: true, SingleFactor: true},
		// Admin WITH a second factor → nothing.
		{UserEmail: "boss@contoso.example", At: base.Add(2 * time.Hour), Success: true, SingleFactor: false},
		// Failed single-factor attempt is not a completed sign-in.
		{UserEmail: "boss@contoso.example", At: base.Add(3 * time.Hour), Success: false, SingleFactor: true},
	}, admin, staff)

	got := checks(t, s, "tenant.signin-admin-1fa")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d: %+v", len(got), got)
	}
	if !strings.Contains(got[0].Title, "boss@contoso.example") || !strings.Contains(got[0].Title, "2 sign-ins") {
		t.Errorf("title = %q", got[0].Title)
	}
	if got[0].Severity != core.SeverityCritical {
		t.Errorf("severity = %s", got[0].Severity)
	}
}

// Google reports no per-event authentication strength, so on Workspace this
// check must stay silent rather than claim everyone used MFA.
func TestAdminSingleFactorSilentWithoutAdminRoles(t *testing.T) {
	s := signInState([]SignIn{{UserEmail: "boss@contoso.example", At: base, Success: true, SingleFactor: true}})
	s.Assessed[AreaAdminRoles] = false
	if got := checks(t, s, "tenant.signin-admin-1fa"); len(got) != 0 {
		t.Errorf("want silence, got %+v", got)
	}
}

// --- 3. two countries, too close together -----------------------------------

func TestCountryHop(t *testing.T) {
	cases := []struct {
		name   string
		events []SignIn
		want   int
	}{
		{"different countries 38 minutes apart", []SignIn{
			{UserEmail: "u@contoso.example", At: base, Success: true, Country: "ID", IP: "1.1.1.1"},
			{UserEmail: "u@contoso.example", At: base.Add(38 * time.Minute), Success: true, Country: "VN", IP: "2.2.2.2"},
		}, 1},
		{"same country is a normal day", []SignIn{
			{UserEmail: "u@contoso.example", At: base, Success: true, Country: "ID"},
			{UserEmail: "u@contoso.example", At: base.Add(10 * time.Minute), Success: true, Country: "ID"},
		}, 0},
		{"different countries far enough apart to travel", []SignIn{
			{UserEmail: "u@contoso.example", At: base, Success: true, Country: "ID"},
			{UserEmail: "u@contoso.example", At: base.Add(6 * time.Hour), Success: true, Country: "VN"},
		}, 0},
		{"a failed sign-in abroad is not a hop", []SignIn{
			{UserEmail: "u@contoso.example", At: base, Success: true, Country: "ID"},
			{UserEmail: "u@contoso.example", At: base.Add(5 * time.Minute), Success: false, Country: "VN"},
		}, 0},
		{"two different users are not one traveller", []SignIn{
			{UserEmail: "a@contoso.example", At: base, Success: true, Country: "ID"},
			{UserEmail: "b@contoso.example", At: base.Add(5 * time.Minute), Success: true, Country: "VN"},
		}, 0},
		{"no country reported → nothing to compare", []SignIn{
			{UserEmail: "u@contoso.example", At: base, Success: true, IP: "1.1.1.1"},
			{UserEmail: "u@contoso.example", At: base.Add(5 * time.Minute), Success: true, IP: "2.2.2.2"},
		}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checks(t, signInState(tc.events), "tenant.signin-country-hop")
			if len(got) != tc.want {
				t.Fatalf("want %d findings, got %d: %+v", tc.want, len(got), got)
			}
			if tc.want == 1 {
				if !strings.Contains(got[0].Title, "38 minutes") {
					t.Errorf("title should state the observed gap: %q", got[0].Title)
				}
				// The finding must show both sign-ins so a VPN can be ruled out
				// by a human rather than by us guessing.
				if _, ok := got[0].Evidence["first"]; !ok {
					t.Error("evidence must carry both sign-ins")
				}
				if !strings.Contains(got[0].Remediation, "VPN") {
					t.Error("remediation must admit the VPN false-positive case")
				}
			}
		})
	}
}

// On Workspace there is no country, so Google's own verdict is surfaced.
func TestGoogleSuspiciousFlagIsSurfaced(t *testing.T) {
	s := signInState([]SignIn{
		{UserEmail: "u@contoso.example", At: base, Success: true, IP: "3.3.3.3", ProviderFlaggedSuspicious: true},
	})
	s.Provider = ProviderGWS

	got := checks(t, s, "tenant.signin-suspicious")
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
	if !strings.Contains(got[0].Remediation, "Google raised this flag itself") {
		t.Errorf("must attribute the verdict to Google: %q", got[0].Remediation)
	}
}

// --- 4. password spray that landed ------------------------------------------

func spray(ip string, failures, accounts int, start time.Time) []SignIn {
	var out []SignIn
	for i := 0; i < failures; i++ {
		out = append(out, SignIn{
			UserEmail: "user" + string(rune('a'+i%accounts)) + "@contoso.example",
			At:        start.Add(time.Duration(i) * time.Minute),
			Success:   false, IP: ip, FailureCode: "50126",
		})
	}
	return out
}

func TestSprayLanded(t *testing.T) {
	t.Run("burst then a success is an incident", func(t *testing.T) {
		events := spray("9.9.9.9", 12, 6, base)
		events = append(events, SignIn{
			UserEmail: "usera@contoso.example", At: base.Add(20 * time.Minute), Success: true, IP: "9.9.9.9",
		})
		got := checks(t, signInState(events), "tenant.signin-spray")
		if len(got) != 1 {
			t.Fatalf("want 1 finding, got %d", len(got))
		}
		if got[0].Severity != core.SeverityCritical {
			t.Errorf("severity = %s", got[0].Severity)
		}
		if !strings.Contains(got[0].Title, "usera@contoso.example") {
			t.Errorf("title must name the account that fell: %q", got[0].Title)
		}
	})

	t.Run("a spray that never lands is noise, not a finding", func(t *testing.T) {
		got := checks(t, signInState(spray("9.9.9.9", 20, 8, base)), "tenant.signin-spray")
		if len(got) != 0 {
			t.Fatalf("want silence, got %+v", got)
		}
	})

	t.Run("nine failures is below the bar", func(t *testing.T) {
		events := append(spray("9.9.9.9", 9, 6, base),
			SignIn{UserEmail: "usera@contoso.example", At: base.Add(20 * time.Minute), Success: true, IP: "9.9.9.9"})
		if got := checks(t, signInState(events), "tenant.signin-spray"); len(got) != 0 {
			t.Fatalf("want silence, got %+v", got)
		}
	})

	t.Run("one person failing repeatedly is not a spray", func(t *testing.T) {
		var events []SignIn
		for i := 0; i < 15; i++ {
			events = append(events, SignIn{
				UserEmail: "forgetful@contoso.example", At: base.Add(time.Duration(i) * time.Minute),
				Success: false, IP: "9.9.9.9",
			})
		}
		events = append(events, SignIn{
			UserEmail: "forgetful@contoso.example", At: base.Add(20 * time.Minute), Success: true, IP: "9.9.9.9",
		})
		if got := checks(t, signInState(events), "tenant.signin-spray"); len(got) != 0 {
			t.Fatalf("15 failures from ONE account must not be a spray: %+v", got)
		}
	})

	t.Run("failures spread over days are not one burst", func(t *testing.T) {
		var events []SignIn
		for i := 0; i < 12; i++ {
			events = append(events, SignIn{
				UserEmail: "user" + string(rune('a'+i%6)) + "@contoso.example",
				At:        base.Add(time.Duration(i) * 6 * time.Hour),
				Success:   false, IP: "9.9.9.9",
			})
		}
		events = append(events, SignIn{UserEmail: "usera@contoso.example", At: base.Add(80 * time.Hour), Success: true, IP: "9.9.9.9"})
		if got := checks(t, signInState(events), "tenant.signin-spray"); len(got) != 0 {
			t.Fatalf("want silence, got %+v", got)
		}
	})
}

// Findings must be stable across runs: the reconcile engine keys on the
// fingerprint, so map iteration order must never leak into the output.
func TestSignInFindingsAreDeterministic(t *testing.T) {
	events := []SignIn{
		{UserEmail: "a@contoso.example", At: base, Success: true, LegacyAuth: true, ClientApp: "IMAP4"},
		{UserEmail: "b@contoso.example", At: base, Success: true, LegacyAuth: true, ClientApp: "POP3"},
		{UserEmail: "c@contoso.example", At: base, Success: true, LegacyAuth: true, ClientApp: "SMTP"},
	}
	first := checks(t, signInState(events), "tenant.signin-legacy-auth")
	for i := 0; i < 20; i++ {
		again := checks(t, signInState(events), "tenant.signin-legacy-auth")
		for j := range first {
			if first[j].Fingerprint != again[j].Fingerprint {
				t.Fatalf("order changed between runs at %d", j)
			}
		}
	}
}
