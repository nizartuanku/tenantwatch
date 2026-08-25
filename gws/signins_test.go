package gws

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/tenantwatch/tenant"
)

func at(y, m, d, hh int) time.Time {
	return time.Date(y, time.Month(m), d, hh, 0, 0, 0, time.UTC)
}

// The Reports API shape, as Google actually returns it: one item per event
// batch, with the interesting facts buried in name/value parameter pairs.
const loginBody = `{"items":[
 {"id":{"time":"2026-08-24T03:14:00.000Z"},"actor":{"email":"Sales@Contoso.co.id"},
  "ipAddress":"203.0.113.9",
  "events":[{"name":"login_success","parameters":[
    {"name":"login_type","value":"google_password"},
    {"name":"is_suspicious","boolValue":true}]}]},
 {"id":{"time":"2026-08-24T04:00:00.000Z"},"actor":{"email":"boss@contoso.co.id"},
  "ipAddress":"198.51.100.2",
  "events":[{"name":"login_failure","parameters":[
    {"name":"login_failure_type","value":"login_failure_invalid_password"}]}]},
 {"id":{"time":"2026-08-24T05:00:00.000Z"},"actor":{"email":"boss@contoso.co.id"},
  "events":[{"name":"login_challenge","parameters":[]}]},
 {"id":{"time":"not-a-time"},"actor":{"email":"broken@contoso.co.id"},
  "events":[{"name":"login_success","parameters":[]}]}
]}`

func TestGoogleSignInMapping(t *testing.T) {
	p := &Provider{
		ReportsURL: "https://stub",
		Fetch:      func(context.Context, string, string) ([]byte, error) { return []byte(loginBody), nil },
	}
	events, assessed, note := p.signIns(context.Background(), "tok", at(2026, 8, 25, 0))
	if !assessed || note != "" {
		t.Fatalf("assessed=%v note=%q", assessed, note)
	}
	// login_challenge is neither a success nor a failure to authenticate, and an
	// event with no usable timestamp cannot be judged — both are dropped.
	if len(events) != 2 {
		t.Fatalf("want 2 usable events, got %d: %+v", len(events), events)
	}

	a := events[0]
	if a.UserEmail != "sales@contoso.co.id" {
		t.Errorf("email not normalised: %q", a.UserEmail)
	}
	if !a.Success || !a.ProviderFlaggedSuspicious {
		t.Errorf("suspicious success mapped wrong: %+v", a)
	}
	if a.ClientApp != "google_password" || a.IP != "203.0.113.9" {
		t.Errorf("client/IP mapped wrong: %+v", a)
	}

	b := events[1]
	if b.Success || b.FailureCode != "login_failure_invalid_password" {
		t.Errorf("failure mapped wrong: %+v", b)
	}
}

// Google reports neither a country nor a per-event authentication strength.
// Leaving those fields zero is what keeps the two-country check and the
// admin-without-MFA sign-in check silent on Workspace instead of guessing —
// so this asserts the ABSENCE, which is the part that would regress quietly.
func TestGoogleLeavesWhatItCannotKnowEmpty(t *testing.T) {
	p := &Provider{
		ReportsURL: "https://stub",
		Fetch:      func(context.Context, string, string) ([]byte, error) { return []byte(loginBody), nil },
	}
	events, _, _ := p.signIns(context.Background(), "tok", at(2026, 8, 25, 0))
	for _, e := range events {
		if e.Country != "" {
			t.Errorf("Google does not report a country; got %q", e.Country)
		}
		if e.SingleFactor {
			t.Errorf("Google does not report auth strength; SingleFactor must stay false: %+v", e)
		}
		if e.LegacyAuth {
			t.Errorf("Google's login_type is not Microsoft's client classification: %+v", e)
		}
	}
}

// Two sign-ins from two countries would normally fire the impossible-travel
// check. With Google's data they must not, because the country is unknown —
// silence here is correctness, not a miss.
func TestNoCountryMeansNoTravelFinding(t *testing.T) {
	now := at(2026, 8, 25, 0)
	st := tenant.TenantState{
		Provider: tenant.ProviderGWS, Domain: "contoso.co.id", TakenAt: now,
		Assessed: map[string]bool{tenant.AreaSignIn: true},
		SignIns: []tenant.SignIn{
			{UserEmail: "sari@contoso.co.id", At: now.Add(-2 * time.Hour), Success: true, IP: "198.51.100.77"},
			{UserEmail: "sari@contoso.co.id", At: now.Add(-90 * time.Minute), Success: true, IP: "203.0.113.212"},
		},
	}
	for _, f := range tenant.Evaluate(st) {
		if strings.Contains(f.Check, "country-hop") {
			t.Fatalf("fired a travel finding without country data: %+v", f)
		}
	}
}

// A tenant whose service account lacks the Reports scope must be told, and must
// end up unassessed — never silently clean.
func TestReportsRefusalIsSurfaced(t *testing.T) {
	p := &Provider{
		ReportsURL: "https://stub",
		Fetch: func(context.Context, string, string) ([]byte, error) {
			return nil, errors.New("403 Forbidden: Insufficient permission")
		},
	}
	events, assessed, note := p.signIns(context.Background(), "tok", at(2026, 8, 25, 0))
	if assessed {
		t.Fatal("a refused audit must not be reported as assessed")
	}
	if len(events) != 0 {
		t.Errorf("got %d events from a refused audit", len(events))
	}
	if !strings.Contains(note, "admin.reports.audit.readonly") {
		t.Errorf("the note must name the scope to grant: %q", note)
	}
	if !strings.Contains(note, "domain-wide delegation") {
		t.Errorf("the note must name the mechanism, which is where this usually fails: %q", note)
	}
}
