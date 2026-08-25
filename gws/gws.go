// Package gws is TenantWatch's Google Workspace provider: it reads a tenant's
// security posture from the Admin SDK Directory API, read-only, and maps it onto
// the provider-neutral tenant.TenantState. As with the M365 provider, the token
// and HTTP fetch are injected so the mapping is tested offline; the live wiring
// (service-account JWT with domain-wide delegation) runs only against a real
// tenant.
//
// Coverage is honest about Google's API shape: the Directory API gives us users
// with 2-step-verification enrolment, admin flags, and last-login — so MFA,
// admin roles, and inactive accounts are assessed directly. OAuth token audit
// and Drive sharing policy live in other APIs (Reports, Drive settings) and are
// surfaced as manual-review notes in v0 rather than guessed.
package gws

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nizartuanku/tenantwatch/dnsauth"
	"github.com/nizartuanku/tenantwatch/tenant"
)

// Fetcher GETs an Admin SDK URL with a bearer token. Injected for offline tests.
type Fetcher func(ctx context.Context, url, bearer string) ([]byte, error)

// Tokener returns an access token for the delegated admin. Injected in tests.
type Tokener func(ctx context.Context) (string, error)

// Provider reads one Google Workspace tenant.
type Provider struct {
	Token   Tokener
	Fetch   Fetcher
	DNS     dnsauth.Resolver
	BaseURL string // default https://admin.googleapis.com/admin/directory/v1
	// ReportsURL overrides the Admin SDK Reports API root (tests).
	ReportsURL string

	// Now is injectable so the sign-in window is deterministic in tests.
	Now func() time.Time
}

func (p *Provider) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

const defaultBase = "https://admin.googleapis.com/admin/directory/v1"

// Snapshot builds a posture snapshot for the tenant.
func (p *Provider) Snapshot(ctx context.Context, domain string) (tenant.TenantState, error) {
	tok, err := p.Token(ctx)
	if err != nil {
		return tenant.TenantState{}, fmt.Errorf("gws auth failed for %s: %w", domain, err)
	}
	st := tenant.TenantState{
		Provider: tenant.ProviderGWS,
		Domain:   domain,
		Assessed: map[string]bool{},
	}

	users, err := p.users(ctx, tok, domain)
	if err != nil {
		return tenant.TenantState{}, fmt.Errorf("gws read users for %s: %w", domain, err)
	}
	st.Users = users
	// The Directory API returns these fields for every user in one call.
	st.Assessed[tenant.AreaMFA] = true
	st.Assessed[tenant.AreaAdminRoles] = true
	st.Assessed[tenant.AreaInactiveUser] = true

	if p.DNS != nil {
		st.Domains = dnsauth.EmailAuth(ctx, p.DNS, domain)
		st.Assessed[tenant.AreaEmailAuth] = true
	}

	// Login audit. Google has no premium-licence gate here, but it also reports
	// no country and no per-event authentication strength — so two of the four
	// detections stay silent on Workspace, and say so.
	if events, ok, note := p.signIns(ctx, tok, p.now()); ok {
		st.SignIns = events
		st.Assessed[tenant.AreaSignIn] = true
		if note != "" {
			st.Notes = append(st.Notes, note)
		}
		st.Notes = append(st.Notes,
			"Google does not report a country or the authentication strength per login, so "+
				"two-country and admin-without-MFA sign-in checks cannot be assessed on Workspace")
	} else {
		st.Notes = append(st.Notes, note)
	}

	// Honest v0 limits for Google Workspace.
	st.Notes = append(st.Notes,
		"third-party OAuth token audit needs the Reports API — assess manually",
		"Drive external-sharing policy needs Drive settings — assess manually",
		"IMAP/POP legacy access is per-user in Gmail settings — assess manually")

	return st, nil
}

// gUser mirrors the Directory API user resource fields we consume.
type gUser struct {
	PrimaryEmail string `json:"primaryEmail"`
	Name         struct {
		FullName string `json:"fullName"`
	} `json:"name"`
	Suspended        bool   `json:"suspended"`
	IsAdmin          bool   `json:"isAdmin"`
	IsDelegatedAdmin bool   `json:"isDelegatedAdmin"`
	IsEnrolledIn2Sv  bool   `json:"isEnrolledIn2Sv"`
	IsEnforcedIn2Sv  bool   `json:"isEnforcedIn2Sv"`
	LastLoginTime    string `json:"lastLoginTime"`
}

func (p *Provider) users(ctx context.Context, tok, domain string) ([]tenant.User, error) {
	base := p.BaseURL
	if base == "" {
		base = defaultBase
	}
	url := base + "/users?domain=" + domain + "&maxResults=500&projection=full"
	body, err := p.Fetch(ctx, url, tok)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Users []gUser `json:"users"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	out := make([]tenant.User, 0, len(resp.Users))
	for _, u := range resp.Users {
		user := tenant.User{
			Email:       u.PrimaryEmail,
			DisplayName: u.Name.FullName,
			Enabled:     !u.Suspended,
			IsAdmin:     u.IsAdmin || u.IsDelegatedAdmin,
			MFAEnabled:  u.IsEnrolledIn2Sv,
		}
		if user.IsAdmin {
			role := "Delegated admin"
			if u.IsAdmin {
				role = "Super admin"
			}
			user.AdminRoles = []string{role}
		}
		if u.LastLoginTime != "" && u.LastLoginTime != "1970-01-01T00:00:00.000Z" {
			if ts, err := time.Parse(time.RFC3339, u.LastLoginTime); err == nil {
				user.LastActive = ts
			}
		}
		out = append(out, user)
	}
	return out, nil
}
