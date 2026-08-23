package graph

import (
	"context"
	"strings"
	"testing"

	"github.com/nizartuanku/tenantwatch/dnsauth"
	"github.com/nizartuanku/tenantwatch/tenant"
)

func fakeFetch(routes map[string]string) Fetcher {
	return func(_ context.Context, url, _ string) ([]byte, error) {
		for frag, body := range routes {
			if strings.Contains(url, frag) {
				return []byte(body), nil
			}
		}
		return []byte(`{"value":[]}`), nil
	}
}

func fakeDNS(m map[string][]string) dnsauth.Resolver {
	return func(_ context.Context, name string) ([]string, error) { return m[name], nil }
}

func TestGraphSnapshotMapsPosture(t *testing.T) {
	routes := map[string]string{
		"/users?": `{"value":[
			{"id":"1","userPrincipalName":"ceo@contoso.com","displayName":"CEO","accountEnabled":true},
			{"id":"2","userPrincipalName":"staff@contoso.com","displayName":"Staff","accountEnabled":true}]}`,
		"userRegistrationDetails": `{"value":[
			{"id":"1","isMfaRegistered":false},
			{"id":"2","isMfaRegistered":true}]}`,
		"/directoryRoles":            `{"value":[{"displayName":"Global Administrator","members":[{"id":"1"}]}]}`,
		"/servicePrincipals":         `{"value":[{"id":"sp1","appId":"app-1","displayName":"MailBot","publisherName":"Acme"}]}`,
		"/oauth2PermissionGrants":    `{"value":[{"clientId":"sp1","consentType":"AllPrincipals","scope":"Mail.ReadWrite offline_access"}]}`,
		"conditionalAccess/policies": `{"value":[{"state":"enabled"}]}`,
		"authorizationPolicy":        `{"blockLegacyAuthentication":false}`,
		"sharepoint/settings":        `{"sharingCapability":"ExternalUserAndGuestSharing"}`,
	}
	p := &Provider{
		Token: func(context.Context) (string, error) { return "tok", nil },
		Fetch: fakeFetch(routes),
		DNS:   fakeDNS(map[string][]string{"contoso.com": {"v=spf1 include:x -all"}, "_dmarc.contoso.com": {"v=DMARC1; p=none"}}),
	}
	st, err := p.Snapshot(context.Background(), "contoso.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Users) != 2 {
		t.Fatalf("users = %d", len(st.Users))
	}
	// CEO is admin, no MFA.
	var ceo tenant.User
	for _, u := range st.Users {
		if u.Email == "ceo@contoso.com" {
			ceo = u
		}
	}
	if !ceo.IsAdmin || ceo.MFAEnabled {
		t.Errorf("ceo should be admin without MFA, got %+v", ceo)
	}
	if len(st.Grants) != 1 || st.Grants[0].ConsentType != "AllPrincipals" {
		t.Errorf("oauth grant mapping wrong: %+v", st.Grants)
	}
	if !st.ConditionalAccess {
		t.Errorf("conditional access should be enforced")
	}
	if !st.LegacyAuthEnabled {
		t.Errorf("legacy auth should read as enabled (blockLegacyAuthentication=false)")
	}
	if !st.Sharing.AnyoneLinks {
		t.Errorf("sharing should map anyone-links")
	}
	if len(st.Domains) != 1 || st.Domains[0].DMARCPolicy != "none" || !st.Domains[0].SPF {
		t.Errorf("email auth mapping wrong: %+v", st.Domains)
	}

	// The mapped state must drive the expected findings end-to-end.
	got := map[string]bool{}
	for _, f := range tenant.Evaluate(st) {
		got[f.Check] = true
	}
	for _, want := range []string{"tenant.admin-mfa", "tenant.risky-oauth", "tenant.legacy-auth", "tenant.external-sharing", "tenant.email-auth"} {
		if !got[want] {
			t.Errorf("expected %s to fire from graph snapshot", want)
		}
	}
	// CA enforced → no-conditional-access must NOT fire.
	if got["tenant.no-conditional-access"] {
		t.Errorf("conditional-access finding should not fire when a policy is enabled")
	}
}
