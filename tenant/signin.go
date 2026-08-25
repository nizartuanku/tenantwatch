package tenant

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nizartuanku/tenantwatch/core"
)

// Sign-in Watch: the half of the picture configuration checks cannot see.
//
// A configuration check says "legacy authentication is still allowed". A
// sign-in check says "someone signed in with it from Vietnam at 03:14, and it
// worked". The first competes with fifty other policy notes; the second is an
// incident. Identity is the number one way a small business gets breached, and
// the sign-in log is the only place it shows up.
//
// Every detection below is a PURE function over one fetched window — no stored
// state, no baseline to warm up, nothing persisted. The log itself is read,
// judged and dropped; only findings survive. That keeps the whole judgement
// exhaustively testable offline, exactly like the configuration checks.

// SignInWindow is how far back the providers fetch. Seven days is the shortest
// retention any tenant has (Microsoft Entra ID Free keeps exactly that), so the
// window fits every customer rather than only the well-licensed ones.
const SignInWindow = 7 * 24 * time.Hour

// Detection thresholds. Deliberately conservative: a detection that cries wolf
// costs more than one that stays quiet, because the whole product's value is
// that its findings are worth reading.
const (
	// TravelWindow — two successful sign-ins from different countries closer
	// together than this are reported. No distance maths and no geo database:
	// we report exactly what was observed and let the operator judge, because
	// pretending to compute an implied airspeed from a country name would be
	// dressing a guess up as a measurement.
	TravelWindow = time.Hour

	// SprayWindow bounds the failure burst that defines a password spray.
	SprayWindow = time.Hour
	// SprayMinFailures / SprayMinAccounts — a spray is broad, not deep: many
	// accounts tried a few times each, which is what distinguishes it from one
	// person fat-fingering their own password.
	SprayMinFailures = 10
	SprayMinAccounts = 5
)

// SignIn is one authentication event, normalised across clouds. A provider
// fills only the fields its API actually reports; anything unknown stays zero
// rather than being guessed, and the checks skip what they cannot judge.
type SignIn struct {
	UserEmail string
	At        time.Time
	Success   bool

	// Country is the country the cloud reported for the sign-in. Empty when the
	// provider does not report one (Google's login activities give an IP but no
	// country), which makes the travel check skip that event rather than invent
	// a location for it.
	Country string
	IP      string

	// ClientApp is the client the cloud named, e.g. "IMAP4", "Browser".
	ClientApp string
	// LegacyAuth is true when the sign-in used a protocol that cannot carry a
	// second factor (IMAP/POP/SMTP AUTH and friends).
	LegacyAuth bool
	// SingleFactor is true when the cloud confirmed only one factor was used.
	// False also means "not reported" — the admin-MFA check therefore requires
	// the provider to have assessed this area at all.
	SingleFactor bool

	// ProviderFlaggedSuspicious carries the cloud's own verdict (Google sets
	// is_suspicious on login events). We surface it rather than second-guess it.
	ProviderFlaggedSuspicious bool

	FailureCode string
}

// checkSignIns runs the four sign-in detections. Silent unless the provider
// actually read the log — an unread log must never look like a clean one.
func checkSignIns(target string, s TenantState) []core.Finding {
	if !s.Assessed[AreaSignIn] {
		return nil
	}
	var out []core.Finding
	out = append(out, checkLegacyAuthSuccess(target, s)...)
	out = append(out, checkAdminSingleFactor(target, s)...)
	out = append(out, checkCountryHop(target, s)...)
	out = append(out, checkSprayLanded(target, s)...)
	return out
}

// checkLegacyAuthSuccess — the strongest finding in the product. Not an opinion
// about policy: proof that a door which cannot carry MFA is open AND in use.
// Aggregated per user and client so a mail client polling every five minutes is
// one finding, not three hundred.
func checkLegacyAuthSuccess(target string, s TenantState) []core.Finding {
	type key struct{ user, app string }
	agg := map[key]*struct {
		count int
		last  time.Time
		from  map[string]bool
	}{}

	for _, e := range s.SignIns {
		if !e.Success || !e.LegacyAuth {
			continue
		}
		k := key{strings.ToLower(e.UserEmail), e.ClientApp}
		a := agg[k]
		if a == nil {
			a = &struct {
				count int
				last  time.Time
				from  map[string]bool
			}{from: map[string]bool{}}
			agg[k] = a
		}
		a.count++
		if e.At.After(a.last) {
			a.last = e.At
		}
		if e.Country != "" {
			a.from[e.Country] = true
		}
	}

	out := make([]core.Finding, 0, len(agg))
	for k, a := range agg {
		where := ""
		if len(a.from) > 0 {
			where = " from " + strings.Join(sortedKeys(a.from), ", ")
		}
		out = append(out, core.Finding{
			Fingerprint: core.Fingerprint(ModuleID, target, "tenant.signin-legacy-auth", k.user+"|"+k.app),
			Target:      target,
			Check:       "tenant.signin-legacy-auth",
			Title: fmt.Sprintf("Legacy authentication succeeded: %s via %s%s (%s in the last 7 days)",
				k.user, clientLabel(k.app), where, plural(a.count, "sign-in")),
			Severity: core.SeverityCritical,
			Remediation: "Block legacy authentication for " + k.user + " and move this client to modern authentication. " +
				"Legacy protocols cannot carry MFA, so this account is effectively password-only today.",
			Evidence: map[string]any{
				"user": k.user, "client": k.app, "sign_ins": a.count,
				"last_seen": a.last.UTC().Format(time.RFC3339),
				"countries": sortedKeys(a.from), "provider": s.Provider,
			},
		})
	}
	sortFindings(out)
	return out
}

// checkAdminSingleFactor — the configuration check says an admin *has* no MFA;
// this says an admin actually *signed in* without one. Requires the provider to
// report authentication strength, which Microsoft does and Google does not.
func checkAdminSingleFactor(target string, s TenantState) []core.Finding {
	if !s.Assessed[AreaAdminRoles] {
		return nil
	}
	admins := map[string][]string{}
	for _, u := range s.Users {
		if u.IsAdmin {
			admins[strings.ToLower(u.Email)] = u.AdminRoles
		}
	}

	type agg struct {
		count int
		last  time.Time
	}
	seen := map[string]*agg{}
	for _, e := range s.SignIns {
		user := strings.ToLower(e.UserEmail)
		if !e.Success || !e.SingleFactor {
			continue
		}
		if _, isAdmin := admins[user]; !isAdmin {
			continue
		}
		a := seen[user]
		if a == nil {
			a = &agg{}
			seen[user] = a
		}
		a.count++
		if e.At.After(a.last) {
			a.last = e.At
		}
	}

	out := make([]core.Finding, 0, len(seen))
	for user, a := range seen {
		roles := strings.Join(admins[user], ", ")
		out = append(out, core.Finding{
			Fingerprint: core.Fingerprint(ModuleID, target, "tenant.signin-admin-1fa", user),
			Target:      target,
			Check:       "tenant.signin-admin-1fa",
			Title: fmt.Sprintf("Admin signed in without MFA: %s (%s) — %s in the last 7 days",
				user, roles, plural(a.count, "sign-in")),
			Severity: core.SeverityCritical,
			Remediation: "Require MFA for " + user + " now. This is not a policy gap on paper — the account " +
				"completed a real sign-in with a password alone.",
			Evidence: map[string]any{
				"user": user, "roles": admins[user], "sign_ins": a.count,
				"last_seen": a.last.UTC().Format(time.RFC3339), "provider": s.Provider,
			},
		})
	}
	sortFindings(out)
	return out
}

// checkCountryHop reports one user signing in successfully from two different
// countries inside TravelWindow.
//
// On Google Workspace the login report carries no country, so there is nothing
// to compare; instead Google's own is_suspicious verdict is surfaced. Each cloud
// contributes what it actually knows, and the finding says which is which.
func checkCountryHop(target string, s TenantState) []core.Finding {
	var out []core.Finding

	byUser := map[string][]SignIn{}
	for _, e := range s.SignIns {
		if !e.Success {
			continue
		}
		byUser[strings.ToLower(e.UserEmail)] = append(byUser[strings.ToLower(e.UserEmail)], e)
	}

	for user, events := range byUser {
		sort.Slice(events, func(i, j int) bool { return events[i].At.Before(events[j].At) })

		// Path A — the cloud reports countries (Microsoft).
		var last *SignIn
		for i := range events {
			e := events[i]
			if e.Country == "" {
				continue
			}
			if last != nil && !strings.EqualFold(last.Country, e.Country) {
				if gap := e.At.Sub(last.At); gap < TravelWindow {
					out = append(out, countryHopFinding(target, s, user, *last, e, gap))
					break // one finding per user is enough to act on
				}
			}
			ev := e
			last = &ev
		}

		// Path B — no country available, but the cloud flagged it itself (Google).
		for _, e := range events {
			if e.Country != "" || !e.ProviderFlaggedSuspicious {
				continue
			}
			out = append(out, core.Finding{
				Fingerprint: core.Fingerprint(ModuleID, target, "tenant.signin-suspicious", user),
				Target:      target,
				Check:       "tenant.signin-suspicious",
				Title:       "Google flagged a successful sign-in as suspicious: " + user,
				Severity:    core.SeverityHigh,
				Remediation: "Review this sign-in with " + user + " directly. If they do not recognise it, reset the password " +
					"and revoke active sessions. Google raised this flag itself — TenantWatch is surfacing it, not second-guessing it.",
				Evidence: map[string]any{
					"user": user, "at": e.At.UTC().Format(time.RFC3339),
					"ip": e.IP, "source": "google is_suspicious", "provider": s.Provider,
				},
			})
			break
		}
	}
	sortFindings(out)
	return out
}

func countryHopFinding(target string, s TenantState, user string, a, b SignIn, gap time.Duration) core.Finding {
	return core.Finding{
		Fingerprint: core.Fingerprint(ModuleID, target, "tenant.signin-country-hop", user),
		Target:      target,
		Check:       "tenant.signin-country-hop",
		Title: fmt.Sprintf("Sign-ins from %s and %s within %s: %s",
			a.Country, b.Country, humanGap(gap), user),
		Severity: core.SeverityHigh,
		Remediation: "Confirm with " + user + " that both sign-ins were theirs. If not, reset the password and revoke " +
			"active sessions. A VPN or a corporate egress in another country can explain this — both sign-ins are " +
			"shown below so you can judge rather than guess.",
		Evidence: map[string]any{
			"user":        user,
			"first":       map[string]any{"country": a.Country, "ip": a.IP, "at": a.At.UTC().Format(time.RFC3339)},
			"second":      map[string]any{"country": b.Country, "ip": b.IP, "at": b.At.UTC().Format(time.RFC3339)},
			"gap_minutes": int(gap.Minutes()), "provider": s.Provider,
		},
	}
}

// checkSprayLanded — a password spray is only news when it lands. Failures
// alone are background noise on any internet-facing tenant; a success from the
// same address that just failed against a crowd of accounts is an incident.
func checkSprayLanded(target string, s TenantState) []core.Finding {
	byIP := map[string][]SignIn{}
	for _, e := range s.SignIns {
		if e.IP == "" {
			continue
		}
		byIP[e.IP] = append(byIP[e.IP], e)
	}

	var out []core.Finding
	for ip, events := range byIP {
		sort.Slice(events, func(i, j int) bool { return events[i].At.Before(events[j].At) })

		// Sliding window over the failures from this address.
		for i := range events {
			if events[i].Success {
				continue
			}
			windowEnd := events[i].At.Add(SprayWindow)
			failures, accounts := 0, map[string]bool{}
			for j := i; j < len(events) && !events[j].At.After(windowEnd); j++ {
				if events[j].Success {
					continue
				}
				failures++
				accounts[strings.ToLower(events[j].UserEmail)] = true
			}
			if failures < SprayMinFailures || len(accounts) < SprayMinAccounts {
				continue
			}
			// Did anything from this address succeed during or after the burst?
			var landed *SignIn
			for j := range events {
				if events[j].Success && !events[j].At.Before(events[i].At) {
					ev := events[j]
					landed = &ev
					break
				}
			}
			if landed == nil {
				break // a spray that never landed is noise, not a finding
			}
			out = append(out, core.Finding{
				Fingerprint: core.Fingerprint(ModuleID, target, "tenant.signin-spray", ip),
				Target:      target,
				Check:       "tenant.signin-spray",
				Title: fmt.Sprintf("Password spray succeeded from %s: %d failures across %d accounts, then %s signed in",
					ip, failures, len(accounts), landed.UserEmail),
				Severity: core.SeverityCritical,
				Remediation: "Treat " + landed.UserEmail + " as compromised: reset the password, revoke active sessions, " +
					"and check the mailbox for forwarding rules. Then block " + ip + " and require MFA tenant-wide.",
				Evidence: map[string]any{
					"ip": ip, "failures": failures, "accounts_targeted": len(accounts),
					"compromised_user": strings.ToLower(landed.UserEmail),
					"succeeded_at":     landed.At.UTC().Format(time.RFC3339),
					"provider":         s.Provider,
				},
			})
			break // one finding per address
		}
	}
	sortFindings(out)
	return out
}

// --- helpers ----------------------------------------------------------------

func clientLabel(app string) string {
	if app == "" {
		return "a legacy client"
	}
	return app
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func humanGap(d time.Duration) string {
	m := int(d.Minutes())
	if m < 1 {
		return "under a minute"
	}
	return plural(m, "minute")
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortFindings keeps output deterministic despite map iteration, so the
// dashboard order is stable and the tests are not flaky.
func sortFindings(f []core.Finding) {
	sort.Slice(f, func(i, j int) bool { return f[i].Fingerprint < f[j].Fingerprint })
}
