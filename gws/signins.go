package gws

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/nizartuanku/tenantwatch/tenant"
)

// Reading the Google Workspace login audit.
//
// Google is the easier of the two clouds here: the Admin SDK Reports API exposes
// login activities without the premium-licence gate Microsoft puts on its
// sign-in log, and Google even publishes its own verdict on a login through the
// `is_suspicious` parameter. Where Google has already judged, we surface its
// judgement rather than invent a second one.
//
// What Google does NOT give us, we do not fake:
//   - no country per login (only an IP), so the two-country check has nothing
//     to compare and stays silent on Workspace
//   - no per-event authentication strength, so "admin signed in without MFA"
//     cannot be assessed here at all
//
// Both gaps are reported to the user as unassessed rather than dressed up.

const reportsBase = "https://admin.googleapis.com/admin/reports/v1"

// signInPageLimit bounds pagination for the same reason as the Microsoft side:
// this is a posture report, not a log archive.
const signInPageLimit = 10

// ReportsBase lets tests point the Reports API at a stub. Empty uses the real one.
func (p *Provider) reportsBase() string {
	if p.ReportsURL != "" {
		return p.ReportsURL
	}
	return reportsBase
}

// signIns fetches the last SignInWindow of login activity.
//
// Returns (events, assessed, note) with the same contract as the Microsoft
// provider: assessed=false keeps every sign-in check silent.
func (p *Provider) signIns(ctx context.Context, tok string, now time.Time) ([]tenant.SignIn, bool, string) {
	since := now.Add(-tenant.SignInWindow).UTC().Format(time.RFC3339)
	q := url.Values{}
	q.Set("startTime", since)
	q.Set("maxResults", "1000")
	path := "/activity/users/all/applications/login?" + q.Encode()

	var out []tenant.SignIn
	for page := 0; page < signInPageLimit; page++ {
		body, err := p.Fetch(ctx, p.reportsBase()+path, tok)
		if err != nil {
			return nil, false, "the Google login audit could not be read — check that the service account is granted " +
				"https://www.googleapis.com/auth/admin.reports.audit.readonly with domain-wide delegation"
		}

		var resp struct {
			Items []struct {
				ID struct {
					Time string `json:"time"`
				} `json:"id"`
				Actor struct {
					Email string `json:"email"`
				} `json:"actor"`
				IPAddress string `json:"ipAddress"`
				Events    []struct {
					Name       string `json:"name"`
					Parameters []struct {
						Name      string `json:"name"`
						Value     string `json:"value"`
						BoolValue *bool  `json:"boolValue"`
					} `json:"parameters"`
				} `json:"events"`
			} `json:"items"`
			NextPageToken string `json:"nextPageToken"`
		}
		if json.Unmarshal(body, &resp) != nil {
			return nil, false, "the Google login audit could not be parsed"
		}

		for _, it := range resp.Items {
			at, err := time.Parse(time.RFC3339, it.ID.Time)
			if err != nil {
				continue
			}
			for _, ev := range it.Events {
				kind := strings.ToLower(ev.Name)
				// login_challenge and other event types are neither a success
				// nor a failure to authenticate; judging them would be guessing.
				if kind != "login_success" && kind != "login_failure" {
					continue
				}
				si := tenant.SignIn{
					UserEmail: strings.ToLower(it.Actor.Email),
					At:        at,
					Success:   kind == "login_success",
					IP:        it.IPAddress,
					// Country and SingleFactor are deliberately left zero:
					// Google does not report them, and a zero value here means
					// "unknown", which the checks skip.
				}
				for _, pr := range ev.Parameters {
					switch pr.Name {
					case "is_suspicious":
						si.ProviderFlaggedSuspicious = pr.BoolValue != nil && *pr.BoolValue
					case "login_type":
						si.ClientApp = pr.Value
					case "login_failure_type":
						si.FailureCode = pr.Value
					}
				}
				out = append(out, si)
			}
		}

		if resp.NextPageToken == "" {
			return out, true, ""
		}
		q.Set("pageToken", resp.NextPageToken)
		path = "/activity/users/all/applications/login?" + q.Encode()
	}
	return out, true, "the Google login audit was larger than one scan reads; the newest " +
		"events were assessed and older ones were not"
}
