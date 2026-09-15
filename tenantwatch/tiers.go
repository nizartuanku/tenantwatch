package tenantwatch

import "github.com/nizartuanku/tenantwatch/license"

// TierLimits is what each TenantWatch edition buys.
//
// It lives here, in the product package, rather than in each command, because
// two binaries need it and they must not drift: the shipping binary and the
// demo whose recording is used as the product's screenshot. When the demo fell
// back to the engine's generic defaults it advertised a free edition that does
// not exist (ten tenants instead of one) — the sort of mismatch a buyer finds
// before you do.
//
// The engine's license.TierLimits is a generic default for products whose
// "target" is cheap (a host, a certificate). A tenant is not cheap: one tenant
// is a whole organisation, so the free edition covers exactly one.
//
// This table and the Whop product page are the same claim written twice. Change
// them together.
var TierLimits = map[license.Tier]license.Limits{
	license.TierFree: {
		MaxTargets:    1,
		RetentionDays: 30,
		Channels:      []string{"webhook", "syslog"},
	},
	license.TierPro: {
		MaxTargets:     10,
		RetentionDays:  365,
		Channels:       []string{"webhook", "syslog", "email", "slack", "telegram"},
		CustomInterval: true,
		ScanNow:        true,
	},
	license.TierTeam: {
		MaxTargets:     0, // unlimited
		RetentionDays:  0, // unlimited
		Channels:       []string{"webhook", "syslog", "email", "slack", "telegram", "pagerduty", "teams"},
		MultiUser:      true,
		CustomInterval: true,
		ScanNow:        true,
	},
}

// AllowsChannel reports whether the named notification channel is included in
// the edition the given tier buys.
//
// It reads TierLimits above, not license.TierLimits. The two tables differ —
// TenantWatch's free edition covers one tenant, the engine's generic table
// assumes a cheap target — and a gate that consults the wrong table would
// silently sell, or silently refuse, the wrong thing. Resolve the product's own
// table here so there is exactly one answer to "is Slack part of this edition".
//
// An unknown tier in a signed key falls back to the free edition: the safest
// floor, and the same rule limitsFor applies to capacity.
func AllowsChannel(t license.Tier, name string) bool {
	lim, ok := TierLimits[t]
	if !ok {
		lim = TierLimits[license.TierFree]
	}
	for _, c := range lim.Channels {
		if c == name {
			return true
		}
	}
	return false
}
