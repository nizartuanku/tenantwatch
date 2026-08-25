package graph

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/tenantwatch/tenant"
)

// The exact error Microsoft Graph returns to a tenant without Entra ID P1, as
// the live fetcher surfaces it (status line + body snippet).
const realPremiumError = `GET https://graph.microsoft.com/v1.0/auditLogs/signIns: 403 Forbidden: ` +
	`{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant",` +
	`"message":"Neither tenant is B2C or tenant doesn't have premium license"}}`

func TestPremiumLicenceRefused(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"the real Graph error", errors.New(realPremiumError), true},
		{"code only", errors.New("Authentication_RequestFromNonPremiumTenantOrB2CTenant"), true},
		{"message only", errors.New("Neither tenant is B2C or tenant doesn't have premium license"), true},
		{"British spelling, in case Microsoft ever changes it", errors.New("tenant doesn't have premium licence"), true},
		{"an ordinary permission failure is NOT a licence problem", errors.New("403 Forbidden: Insufficient privileges"), false},
		{"a transient failure is not a licence problem", errors.New("dial tcp: i/o timeout"), false},
		{"no error", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := premiumLicenceRefused(tc.err); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// This is the single most important test in the feature. A tenant that cannot
// be assessed must end up with the log UNASSESSED and a note naming the licence
// — because the check engine turns "unassessed" into silence, and silence plus
// a visible note is honest, while silence alone reads as "you're clean".
func TestTenantWithoutPremiumIsToldNotIgnored(t *testing.T) {
	p := &Provider{
		BaseURL: "https://stub",
		Token:   func(context.Context) (string, error) { return "tok", nil },
		Fetch: func(_ context.Context, u, _ string) ([]byte, error) {
			if strings.Contains(u, "auditLogs/signIns") {
				return nil, errors.New(realPremiumError)
			}
			return []byte(`{"value":[]}`), nil
		},
		Now: func() time.Time { return time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC) },
	}

	events, assessed, note := p.signIns(context.Background(), "tok", p.now())
	if assessed {
		t.Fatal("a refused log must not be reported as assessed")
	}
	if len(events) != 0 {
		t.Errorf("got %d events from a refused log", len(events))
	}
	if !strings.Contains(note, "Entra ID P1") || !strings.Contains(note, "Business Premium") {
		t.Errorf("the note must name the licence AND the plan that includes it: %q", note)
	}
	if !strings.Contains(note, "configuration check") {
		t.Errorf("the note must reassure that the rest still works: %q", note)
	}

	// And end-to-end: the check engine must produce ZERO sign-in findings.
	st := tenant.TenantState{
		Provider: tenant.ProviderM365, Domain: "contoso.example",
		Assessed: map[string]bool{}, Notes: []string{note},
	}
	var signInFindings, noteFindings int
	for _, f := range tenant.Evaluate(st) {
		if strings.HasPrefix(f.Check, "tenant.signin") {
			signInFindings++
		}
		if f.Check == "tenant.manual-review" {
			noteFindings++
		}
	}
	if signInFindings != 0 {
		t.Errorf("want 0 sign-in findings, got %d", signInFindings)
	}
	if noteFindings != 1 {
		t.Errorf("want exactly 1 visible manual-review finding, got %d", noteFindings)
	}
}

// A permission problem is a different blind spot and deserves a different,
// actionable line — naming the two scopes Microsoft actually requires.
func TestOrdinaryFailureNamesTheScopes(t *testing.T) {
	p := &Provider{
		BaseURL: "https://stub",
		Fetch: func(context.Context, string, string) ([]byte, error) {
			return nil, errors.New("403 Forbidden: Insufficient privileges to complete the operation")
		},
	}
	_, assessed, note := p.signIns(context.Background(), "tok", time.Now())
	if assessed {
		t.Fatal("assessed must be false")
	}
	if !strings.Contains(note, "AuditLog.Read.All") || !strings.Contains(note, "Directory.Read.All") {
		t.Errorf("note must name both required permissions: %q", note)
	}
}

func TestSignInMapping(t *testing.T) {
	body := `{"value":[
	  {"userPrincipalName":"Sales@Contoso.Example","createdDateTime":"2026-08-24T03:14:00Z",
	   "ipAddress":"203.0.113.9","clientAppUsed":"IMAP4","authenticationRequirement":"singleFactorAuthentication",
	   "status":{"errorCode":0},"location":{"countryOrRegion":"VN"}},
	  {"userPrincipalName":"boss@contoso.example","createdDateTime":"2026-08-24T04:00:00Z",
	   "ipAddress":"198.51.100.2","clientAppUsed":"Browser","authenticationRequirement":"multiFactorAuthentication",
	   "status":{"errorCode":50126},"location":{"countryOrRegion":"ID"}},
	  {"userPrincipalName":"broken@contoso.example","createdDateTime":"not-a-time",
	   "status":{"errorCode":0}}
	]}`
	p := &Provider{
		BaseURL: "https://stub",
		Fetch:   func(context.Context, string, string) ([]byte, error) { return []byte(body), nil },
	}
	events, assessed, note := p.signIns(context.Background(), "tok", time.Now())
	if !assessed || note != "" {
		t.Fatalf("assessed=%v note=%q", assessed, note)
	}
	// The undated event is dropped: an event we cannot place in time is one we
	// cannot judge.
	if len(events) != 2 {
		t.Fatalf("want 2 usable events, got %d", len(events))
	}

	a := events[0]
	if a.UserEmail != "sales@contoso.example" {
		t.Errorf("email not normalised: %q", a.UserEmail)
	}
	if !a.Success || !a.LegacyAuth || !a.SingleFactor {
		t.Errorf("IMAP4 single-factor success mapped wrong: %+v", a)
	}
	if a.Country != "VN" || a.IP != "203.0.113.9" {
		t.Errorf("location mapped wrong: %+v", a)
	}

	b := events[1]
	if b.Success || b.LegacyAuth || b.SingleFactor {
		t.Errorf("failed MFA browser sign-in mapped wrong: %+v", b)
	}
	if b.FailureCode != "50126" {
		t.Errorf("failure code = %q", b.FailureCode)
	}
}

// Client classification decides whether a sign-in becomes a Critical finding,
// so it errs toward "legacy" for anything Microsoft has not told us is modern —
// but never calls an unknown blank value legacy.
func TestIsLegacyClient(t *testing.T) {
	for app, want := range map[string]bool{
		"IMAP4":                           true,
		"POP3":                            true,
		"Authenticated SMTP":              true,
		"Exchange ActiveSync":             true,
		"Other clients":                   true,
		"Some Future Legacy Protocol":     true,
		"Browser":                         false,
		"Mobile Apps and Desktop clients": false,
		"":                                false,
	} {
		if got := isLegacyClient(app); got != want {
			t.Errorf("isLegacyClient(%q) = %v, want %v", app, got, want)
		}
	}
}
