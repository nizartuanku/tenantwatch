package graph

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nizartuanku/tenantwatch/tenant"
)

// Reading the Microsoft 365 sign-in log.
//
// One thing dominates this file: **`/auditLogs/signIns` requires an Entra ID P1
// or P2 licence.** Microsoft's own documentation is contradictory here — the
// retention page says sign-in logs are available on every tier (Free keeps 7
// days), while the troubleshooting guidance states plainly that this endpoint
// answers `Authentication_RequestFromNonPremiumTenantOrB2CTenant` without
// premium licensing. The second is what a tenant actually experiences.
//
// Entra ID P1 ships with Microsoft 365 Business Premium, but NOT with Business
// Basic or Business Standard — so a large share of small businesses cannot use
// this at all. That is not a reason to fail quietly. A tenant that cannot be
// assessed must be TOLD, in the dashboard, in plain words, and must never see a
// clean bill of health it did not earn.

// signInPageLimit bounds how many pages we will follow. A busy tenant can
// produce a great many sign-ins in seven days; we are building a posture
// report, not archiving the log, so we stop at a sane ceiling rather than
// pulling an unbounded amount into memory.
const signInPageLimit = 10

// legacyClients: Microsoft classifies everything that is not a browser or a
// modern desktop/mobile client as a legacy authentication client. We invert
// that list rather than enumerate every legacy protocol, so a client Microsoft
// adds later is treated as legacy (the safe direction) instead of silently
// modern. An empty value stays unknown and is never called legacy.
func isLegacyClient(clientApp string) bool {
	switch strings.TrimSpace(clientApp) {
	case "", "Browser", "Mobile Apps and Desktop clients":
		return false
	default:
		return true
	}
}

// premiumLicenceRefused reports whether Graph turned us away for lack of an
// Entra ID P1/P2 licence. Both the error code and the human message are matched
// so this keeps working if Microsoft returns one without the other.
func premiumLicenceRefused(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "requestfromnonpremiumtenantorb2ctenant") ||
		strings.Contains(msg, "premium license") ||
		strings.Contains(msg, "premium licence")
}

// LicenceNote is the exact line a tenant without P1 sees in its dashboard. It
// is deliberately specific: it names the licence, names the plan that includes
// it, and reassures that everything else still works — a blind spot the user
// can act on beats a blind spot they never learn about.
const LicenceNote = "sign-in monitoring needs Microsoft Entra ID P1, which this tenant's plan does not include " +
	"(it comes with Microsoft 365 Business Premium). Every configuration check is unaffected."

// signIns fetches the last SignInWindow of sign-ins.
//
// Returns (events, assessed, note). assessed=false with a note means "we could
// not look", which keeps every sign-in check silent rather than clean.
func (p *Provider) signIns(ctx context.Context, tok string, now time.Time) ([]tenant.SignIn, bool, string) {
	since := now.Add(-tenant.SignInWindow).UTC().Format(time.RFC3339)
	path := "/auditLogs/signIns?$filter=" + url.QueryEscape("createdDateTime ge "+since) + "&$top=1000"

	var out []tenant.SignIn
	for page := 0; page < signInPageLimit; page++ {
		body, err := p.get(ctx, tok, path)
		if err != nil {
			if premiumLicenceRefused(err) {
				return nil, false, LicenceNote
			}
			// Anything else (permission missing, transient failure) is still a
			// blind spot the user deserves to see.
			return nil, false, "the sign-in log could not be read — check that the app registration has " +
				"AuditLog.Read.All and Directory.Read.All granted"
		}

		var resp struct {
			Value []struct {
				UserPrincipalName string `json:"userPrincipalName"`
				CreatedDateTime   string `json:"createdDateTime"`
				IPAddress         string `json:"ipAddress"`
				ClientAppUsed     string `json:"clientAppUsed"`
				AuthRequirement   string `json:"authenticationRequirement"`
				Status            struct {
					ErrorCode int `json:"errorCode"`
				} `json:"status"`
				Location struct {
					CountryOrRegion string `json:"countryOrRegion"`
				} `json:"location"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if json.Unmarshal(body, &resp) != nil {
			return nil, false, "the sign-in log could not be parsed"
		}

		for _, e := range resp.Value {
			at, err := time.Parse(time.RFC3339, e.CreatedDateTime)
			if err != nil {
				continue // an event we cannot place in time is one we cannot judge
			}
			out = append(out, tenant.SignIn{
				UserEmail:  strings.ToLower(e.UserPrincipalName),
				At:         at,
				Success:    e.Status.ErrorCode == 0,
				Country:    e.Location.CountryOrRegion,
				IP:         e.IPAddress,
				ClientApp:  e.ClientAppUsed,
				LegacyAuth: isLegacyClient(e.ClientAppUsed),
				// Microsoft states this explicitly, so we never have to infer it.
				SingleFactor: strings.EqualFold(e.AuthRequirement, "singleFactorAuthentication"),
				FailureCode:  failureCode(e.Status.ErrorCode),
			})
		}

		if resp.NextLink == "" {
			return out, true, ""
		}
		// nextLink is absolute; get() prepends the base, so strip it back off.
		path = strings.TrimPrefix(resp.NextLink, p.base())
		if strings.HasPrefix(path, "http") {
			return out, true, "" // unexpected shape — stop with what we have
		}
	}
	// Hit the page ceiling: we have a large, representative sample rather than
	// the whole log. Say so instead of implying completeness.
	return out, true, "the sign-in log was larger than one scan reads; the newest " +
		"events were assessed and older ones were not"
}

func failureCode(code int) string {
	if code == 0 {
		return ""
	}
	return itoa(code)
}

// base returns the Graph root this provider talks to (tests point it at a stub).
func (p *Provider) base() string {
	if p.BaseURL != "" {
		return p.BaseURL
	}
	return defaultBase
}

func itoa(i int) string { return strconv.Itoa(i) }
