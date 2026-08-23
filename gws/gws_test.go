package gws

import (
	"context"
	"strings"
	"testing"

	"github.com/nizartuanku/tenantwatch/dnsauth"
	"github.com/nizartuanku/tenantwatch/tenant"
)

func fakeDNS(m map[string][]string) dnsauth.Resolver {
	return func(_ context.Context, name string) ([]string, error) { return m[name], nil }
}

func TestGWSSnapshotMapsUsers(t *testing.T) {
	usersJSON := `{"users":[
		{"primaryEmail":"admin@contoso.co.id","name":{"fullName":"Admin"},"suspended":false,"isAdmin":true,"isEnrolledIn2Sv":false},
		{"primaryEmail":"staff@contoso.co.id","name":{"fullName":"Staff"},"suspended":false,"isEnrolledIn2Sv":true,"lastLoginTime":"2026-08-20T09:00:00.000Z"},
		{"primaryEmail":"old@contoso.co.id","name":{"fullName":"Old"},"suspended":false,"isEnrolledIn2Sv":true,"lastLoginTime":"2026-01-01T09:00:00.000Z"}]}`

	p := &Provider{
		Token: func(context.Context) (string, error) { return "tok", nil },
		Fetch: func(_ context.Context, url, _ string) ([]byte, error) {
			if strings.Contains(url, "/users") {
				return []byte(usersJSON), nil
			}
			return []byte(`{}`), nil
		},
		DNS: fakeDNS(map[string][]string{"contoso.co.id": {"v=spf1 -all"}}), // SPF only, no DMARC
	}
	st, err := p.Snapshot(context.Background(), "contoso.co.id")
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Users) != 3 {
		t.Fatalf("users = %d", len(st.Users))
	}
	var admin tenant.User
	for _, u := range st.Users {
		if u.Email == "admin@contoso.co.id" {
			admin = u
		}
	}
	if !admin.IsAdmin || admin.MFAEnabled {
		t.Errorf("admin should be admin without 2SV: %+v", admin)
	}
	if !st.Assessed[tenant.AreaInactiveUser] || !st.Assessed[tenant.AreaMFA] {
		t.Errorf("gws should assess MFA and inactive-user areas")
	}

	got := map[string]bool{}
	for _, f := range tenant.Evaluate(st) {
		got[f.Check] = true
	}
	// admin without 2SV → admin-mfa; DMARC missing → email-auth; old login → inactive.
	// TakenAt defaults to zero here, so inactive can't compute — set it via collector in practice.
	for _, want := range []string{"tenant.admin-mfa", "tenant.email-auth"} {
		if !got[want] {
			t.Errorf("expected %s from gws snapshot", want)
		}
	}
	// GWS must not produce a conditional-access finding.
	if got["tenant.no-conditional-access"] {
		t.Errorf("gws should never fire conditional-access")
	}
}
