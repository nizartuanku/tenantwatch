package tenantwatch

import (
	"testing"

	"github.com/nizartuanku/tenantwatch/license"
)

// These numbers are a public promise: they are printed on the product page, in
// the README, and — through the demo dashboard — in the screenshot people
// decide from. They are also the difference between selling Pro and giving it
// away, so they get a test rather than a comment.
func TestFreeEditionCoversExactlyOneTenant(t *testing.T) {
	free := TierLimits[license.TierFree]
	if free.MaxTargets != 1 {
		t.Fatalf("the free edition is advertised as one tenant; table says %d", free.MaxTargets)
	}
	if free.RetentionDays != 30 {
		t.Errorf("free retention is advertised as 30 days; table says %d", free.RetentionDays)
	}
	if free.ScanNow || free.CustomInterval || free.MultiUser {
		t.Errorf("free must not carry paid capabilities: %+v", free)
	}
}

func TestPaidTiersBuySomething(t *testing.T) {
	pro := TierLimits[license.TierPro]
	team := TierLimits[license.TierTeam]

	if pro.MaxTargets <= TierLimits[license.TierFree].MaxTargets {
		t.Errorf("Pro must allow more tenants than free: %d", pro.MaxTargets)
	}
	if !pro.ScanNow || !pro.CustomInterval {
		t.Errorf("Pro is sold on on-demand scans and custom intervals: %+v", pro)
	}
	if team.MaxTargets != 0 || team.RetentionDays != 0 {
		t.Errorf("Team is sold as unlimited (0 means unlimited): %+v", team)
	}
	if !team.MultiUser {
		t.Errorf("Team is sold on multi-user: %+v", team)
	}

	// Every tier must include the channels the tier below it has, or an upgrade
	// would silently take something away.
	for _, step := range []struct {
		lower, higher license.Tier
	}{{license.TierFree, license.TierPro}, {license.TierPro, license.TierTeam}} {
		have := map[string]bool{}
		for _, c := range TierLimits[step.higher].Channels {
			have[c] = true
		}
		for _, c := range TierLimits[step.lower].Channels {
			if !have[c] {
				t.Errorf("%s loses channel %q that %s has", step.higher, c, step.lower)
			}
		}
	}
}
