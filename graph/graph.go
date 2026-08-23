// Package graph is TenantWatch's Microsoft 365 provider: it reads a tenant's
// security posture from Microsoft Graph, read-only, and maps it onto the
// provider-neutral tenant.TenantState the check engine reasons about.
//
// Everything network is injected — the Tokener that acquires an app-only access
// token and the Fetcher that GETs a Graph URL — so the mapping logic is fully
// tested offline against canned Graph JSON. The live wiring (client-credentials
// flow against login.microsoftonline.com, bearer GETs against graph.microsoft.com)
// lives in Live* below and is exercised only against a real tenant.
package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nizartuanku/tenantwatch/dnsauth"
	"github.com/nizartuanku/tenantwatch/tenant"
)

// Fetcher GETs a Graph URL with a bearer token and returns the body. Injected
// for offline tests.
type Fetcher func(ctx context.Context, url, bearer string) ([]byte, error)

// Tokener returns an app-only access token for the tenant. Injected so tests
// need no real credentials.
type Tokener func(ctx context.Context) (string, error)

// Provider reads one M365 tenant.
type Provider struct {
	Token   Tokener
	Fetch   Fetcher
	DNS     dnsauth.Resolver
	BaseURL string // default https://graph.microsoft.com/v1.0
}

const defaultBase = "https://graph.microsoft.com/v1.0"

// Snapshot builds a posture snapshot for the tenant. It gathers each area
// best-effort: an area that errors or is unavailable becomes an honest Note,
// never a false "all clear". Only a total auth failure aborts the snapshot.
func (p *Provider) Snapshot(ctx context.Context, domain string) (tenant.TenantState, error) {
	tok, err := p.Token(ctx)
	if err != nil {
		return tenant.TenantState{}, fmt.Errorf("m365 auth failed for %s: %w", domain, err)
	}
	st := tenant.TenantState{
		Provider: tenant.ProviderM365,
		Domain:   domain,
		Assessed: map[string]bool{},
	}

	users, mfa, err := p.users(ctx, tok)
	if err != nil {
		return tenant.TenantState{}, fmt.Errorf("m365 read users for %s: %w", domain, err)
	}
	st.Users = users
	st.Assessed[tenant.AreaMFA] = mfa

	if roles, ok := p.adminRoles(ctx, tok); ok {
		applyAdminRoles(st.Users, roles)
		st.Assessed[tenant.AreaAdminRoles] = true
	} else {
		st.Notes = append(st.Notes, "administrator roles (directoryRoles) could not be read")
	}

	if grants, ok := p.oauthGrants(ctx, tok); ok {
		st.Grants = grants
		st.Assessed[tenant.AreaOAuth] = true
	} else {
		st.Notes = append(st.Notes, "third-party app consents (oauth2PermissionGrants) could not be read")
	}

	if enforced, ok := p.conditionalAccess(ctx, tok); ok {
		st.ConditionalAccess = enforced
		st.Assessed[tenant.AreaConditional] = true
	} else {
		st.Notes = append(st.Notes, "conditional-access policies could not be read (Entra ID P1 required)")
	}

	if legacy, ok := p.legacyAuth(ctx, tok); ok {
		st.LegacyAuthEnabled = legacy
		st.Assessed[tenant.AreaLegacyAuth] = true
	} else {
		st.Notes = append(st.Notes, "legacy-authentication policy could not be read")
	}

	if sh, ok := p.sharing(ctx, tok); ok {
		st.Sharing = sh
		st.Assessed[tenant.AreaSharing] = true
	} else {
		st.Notes = append(st.Notes, "SharePoint/OneDrive external-sharing setting could not be read")
	}

	if p.DNS != nil {
		st.Domains = dnsauth.EmailAuth(ctx, p.DNS, domain)
		st.Assessed[tenant.AreaEmailAuth] = true
	}

	// Honest v0 limits: sign-in activity and per-mailbox forwarding need extra
	// licensing/permissions, so they are surfaced as manual-review rather than
	// silently assumed clean.
	st.Notes = append(st.Notes,
		"inactive-account review needs sign-in activity (Entra ID P1) — assess manually",
		"external mailbox auto-forwarding needs Exchange mailbox read — assess manually")

	return st, nil
}

// --- users + MFA ------------------------------------------------------------

type gUser struct {
	ID             string `json:"id"`
	UPN            string `json:"userPrincipalName"`
	Display        string `json:"displayName"`
	AccountEnabled bool   `json:"accountEnabled"`
	Mail           string `json:"mail"`
}

func (p *Provider) users(ctx context.Context, tok string) ([]tenant.User, bool, error) {
	body, err := p.get(ctx, tok, "/users?$select=id,userPrincipalName,displayName,accountEnabled,mail&$top=999")
	if err != nil {
		return nil, false, err
	}
	var resp struct {
		Value []gUser `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, false, err
	}
	byID := map[string]int{}
	users := make([]tenant.User, 0, len(resp.Value))
	for _, u := range resp.Value {
		email := u.UPN
		if email == "" {
			email = u.Mail
		}
		users = append(users, tenant.User{
			ID: u.ID, Email: email, DisplayName: u.Display, Enabled: u.AccountEnabled,
		})
		byID[u.ID] = len(users) - 1
	}

	// MFA registration state (best-effort; needs Reports.Read.All).
	mfaOK := false
	if mb, err := p.get(ctx, tok, "/reports/authenticationMethods/userRegistrationDetails?$top=999"); err == nil {
		var mr struct {
			Value []struct {
				ID            string `json:"id"`
				MFACapable    bool   `json:"isMfaCapable"`
				MFARegistered bool   `json:"isMfaRegistered"`
			} `json:"value"`
		}
		if json.Unmarshal(mb, &mr) == nil {
			mfaOK = true
			for _, r := range mr.Value {
				if i, ok := byID[r.ID]; ok {
					users[i].MFAEnabled = r.MFARegistered
				}
			}
		}
	}
	return users, mfaOK, nil
}

// --- admin roles ------------------------------------------------------------

type roleMembers struct {
	Role    string
	Members []string // user ids
}

func (p *Provider) adminRoles(ctx context.Context, tok string) ([]roleMembers, bool) {
	body, err := p.get(ctx, tok, "/directoryRoles?$expand=members")
	if err != nil {
		return nil, false
	}
	var resp struct {
		Value []struct {
			Display string `json:"displayName"`
			Members []struct {
				ID string `json:"id"`
			} `json:"members"`
		} `json:"value"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil, false
	}
	out := make([]roleMembers, 0, len(resp.Value))
	for _, r := range resp.Value {
		rm := roleMembers{Role: r.Display}
		for _, m := range r.Members {
			rm.Members = append(rm.Members, m.ID)
		}
		out = append(out, rm)
	}
	return out, true
}

func applyAdminRoles(users []tenant.User, roles []roleMembers) {
	byID := map[string]int{}
	for i, u := range users {
		byID[u.ID] = i
	}
	for _, r := range roles {
		for _, id := range r.Members {
			if i, ok := byID[id]; ok {
				users[i].IsAdmin = true
				users[i].AdminRoles = append(users[i].AdminRoles, r.Role)
			}
		}
	}
}

// --- oauth grants -----------------------------------------------------------

func (p *Provider) oauthGrants(ctx context.Context, tok string) ([]tenant.OAuthGrant, bool) {
	// servicePrincipals give app display names; oauth2PermissionGrants give the
	// delegated scopes and consent type. Join on clientId.
	spBody, err := p.get(ctx, tok, "/servicePrincipals?$select=id,appId,displayName,publisherName,verifiedPublisher&$top=999")
	if err != nil {
		return nil, false
	}
	var sp struct {
		Value []struct {
			ID        string `json:"id"`
			AppID     string `json:"appId"`
			Display   string `json:"displayName"`
			Publisher string `json:"publisherName"`
			Verified  struct {
				Name string `json:"displayName"`
			} `json:"verifiedPublisher"`
		} `json:"value"`
	}
	if json.Unmarshal(spBody, &sp) != nil {
		return nil, false
	}
	type spInfo struct{ name, appID, publisher string }
	bySP := map[string]spInfo{}
	for _, s := range sp.Value {
		pub := s.Verified.Name
		if pub == "" {
			pub = s.Publisher
		}
		bySP[s.ID] = spInfo{name: s.Display, appID: s.AppID, publisher: pub}
	}

	gBody, err := p.get(ctx, tok, "/oauth2PermissionGrants?$top=999")
	if err != nil {
		return nil, false
	}
	var gr struct {
		Value []struct {
			ClientID    string `json:"clientId"`
			ConsentType string `json:"consentType"`
			Scope       string `json:"scope"`
		} `json:"value"`
	}
	if json.Unmarshal(gBody, &gr) != nil {
		return nil, false
	}
	// Merge multiple grants per client (delegated scopes accumulate).
	merged := map[string]*tenant.OAuthGrant{}
	for _, g := range gr.Value {
		info := bySP[g.ClientID]
		key := g.ClientID
		og := merged[key]
		if og == nil {
			og = &tenant.OAuthGrant{AppID: info.appID, AppName: info.name, Publisher: info.publisher, ConsentType: g.ConsentType}
			if og.AppID == "" {
				og.AppID = g.ClientID
			}
			merged[key] = og
		}
		// AllPrincipals (admin) consent dominates for risk.
		if strings.EqualFold(g.ConsentType, "AllPrincipals") {
			og.ConsentType = "AllPrincipals"
		}
		for _, sc := range strings.Fields(g.Scope) {
			og.Scopes = appendUnique(og.Scopes, sc)
		}
	}
	out := make([]tenant.OAuthGrant, 0, len(merged))
	for _, g := range merged {
		out = append(out, *g)
	}
	return out, true
}

// --- conditional access, legacy auth, sharing -------------------------------

func (p *Provider) conditionalAccess(ctx context.Context, tok string) (bool, bool) {
	body, err := p.get(ctx, tok, "/identity/conditionalAccess/policies?$select=state")
	if err != nil {
		return false, false
	}
	var resp struct {
		Value []struct {
			State string `json:"state"`
		} `json:"value"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return false, false
	}
	for _, pol := range resp.Value {
		if strings.EqualFold(pol.State, "enabled") {
			return true, true
		}
	}
	return false, true
}

func (p *Provider) legacyAuth(ctx context.Context, tok string) (bool, bool) {
	// authenticationMethodsPolicy / authorizationPolicy don't cleanly expose a
	// single "legacy auth blocked" boolean; the reliable signal is whether a
	// conditional-access policy blocks legacy clients. v0 reads the
	// authorizationPolicy default and treats absence of a block as "enabled".
	body, err := p.get(ctx, tok, "/policies/authorizationPolicy")
	if err != nil {
		return false, false
	}
	var resp struct {
		BlockLegacy *bool `json:"blockLegacyAuthentication"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return false, false
	}
	if resp.BlockLegacy == nil {
		return false, false // field absent → can't tell → Note
	}
	return !*resp.BlockLegacy, true
}

func (p *Provider) sharing(ctx context.Context, tok string) (tenant.SharingConfig, bool) {
	body, err := p.get(ctx, tok, "/admin/sharepoint/settings?$select=sharingCapability")
	if err != nil {
		return tenant.SharingConfig{}, false
	}
	var resp struct {
		SharingCapability string `json:"sharingCapability"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return tenant.SharingConfig{}, false
	}
	capb := resp.SharingCapability
	return tenant.SharingConfig{
		AnyoneLinks:     strings.EqualFold(capb, "ExternalUserAndGuestSharing"),
		ExternalSharing: strings.Contains(strings.ToLower(capb), "external"),
		Level:           capb,
	}, true
}

// --- helpers ----------------------------------------------------------------

func (p *Provider) get(ctx context.Context, tok, path string) ([]byte, error) {
	base := p.BaseURL
	if base == "" {
		base = defaultBase
	}
	return p.Fetch(ctx, base+path, tok)
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
