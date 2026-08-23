package tenant

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nizartuanku/tenantwatch/core"
	"github.com/nizartuanku/tenantwatch/store"
)

type fakeSource struct {
	state TenantState
	err   error
}

func (f fakeSource) Snapshot(_ context.Context, provider, domain string) (TenantState, error) {
	if f.err != nil {
		return TenantState{}, f.err
	}
	s := f.state
	s.Provider, s.Domain = provider, domain
	return s, nil
}

func TestValidateTarget(t *testing.T) {
	c := New(fakeSource{})
	ok := []string{"m365:contoso.onmicrosoft.com", "gws:contoso.co.id", "M365:Contoso.CO.ID"}
	for _, raw := range ok {
		if _, err := c.ValidateTarget(raw); err != nil {
			t.Errorf("%q should validate: %v", raw, err)
		}
	}
	bad := []string{"contoso.co.id", "aws:contoso.co.id", "m365:localhost", "m365:"}
	for _, raw := range bad {
		if _, err := c.ValidateTarget(raw); err == nil {
			t.Errorf("%q should be rejected", raw)
		}
	}
}

func TestCollectEvaluatesSnapshot(t *testing.T) {
	st := richState()
	st.Assessed = map[string]bool{AreaMFA: true, AreaAdminRoles: true}
	// Only an admin without MFA remains interesting.
	st.Users = []User{{Email: "ceo@x.io", Enabled: true, IsAdmin: true, AdminRoles: []string{"Global Administrator"}, MFAEnabled: false}}
	st.Grants = nil
	st.LegacyAuthEnabled = false
	c := New(fakeSource{state: st})
	fs, err := c.Collect(context.Background(), mustTarget(t, c, "m365:x.io"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range fs {
		if f.Check == "tenant.admin-mfa" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected admin-mfa finding, got %d findings", len(fs))
	}
}

func TestSnapshotErrorIsNotAFinding(t *testing.T) {
	c := New(fakeSource{err: errors.New("auth failed")})
	if _, err := c.Collect(context.Background(), mustTarget(t, c, "m365:x.io")); err == nil {
		t.Fatal("a snapshot error must propagate as an error, not silently resolve findings")
	}
}

// Fixing the posture (next snapshot no longer produces the finding) auto-resolves it.
func TestFindingAutoResolvesWhenFixed(t *testing.T) {
	target := "m365:x.io"
	mem := store.NewMemStore()
	eng := store.NewEngine(mem)

	bad := TenantState{Assessed: map[string]bool{AreaMFA: true, AreaAdminRoles: true},
		Users: []User{{Email: "ceo@x.io", Enabled: true, IsAdmin: true, MFAEnabled: false}}}
	c := New(fakeSource{state: bad}).WithClock(func() time.Time { return time.Unix(0, 0) })
	cur, _ := c.Collect(context.Background(), mustTarget(t, c, target))
	info := c.Describe()
	res, _ := eng.Reconcile(info, target, cur)
	if len(res.NewlyOpen) != 1 {
		t.Fatalf("want 1 newly open, got %d", len(res.NewlyOpen))
	}

	good := bad
	good.Users = []User{{Email: "ceo@x.io", Enabled: true, IsAdmin: true, MFAEnabled: true}}
	c2 := New(fakeSource{state: good})
	cur2, _ := c2.Collect(context.Background(), mustTarget(t, c2, target))
	// ResolveAfter is 2, so it resolves on the second consecutive clean scan.
	eng.Reconcile(info, target, cur2)
	res3, _ := eng.Reconcile(info, target, cur2)
	if len(res3.Resolved) != 1 {
		t.Fatalf("want 1 resolved after fix, got %d", len(res3.Resolved))
	}
}

func mustTarget(t *testing.T, c *Collector, raw string) (out core.Target) {
	t.Helper()
	tg, err := c.ValidateTarget(raw)
	if err != nil {
		t.Fatalf("validate %q: %v", raw, err)
	}
	return tg
}
