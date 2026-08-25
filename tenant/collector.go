package tenant

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nizartuanku/tenantwatch/core"
)

// Source produces a posture snapshot for one tenant. The live implementation
// (tenantwatch.MultiSource routing to the graph/ and gws/ providers) talks to
// Microsoft Graph or the Google Admin SDK; tests inject a fake that returns a
// canned TenantState. This is the seam that keeps the whole check engine
// offline-testable.
type Source interface {
	Snapshot(ctx context.Context, provider, domain string) (TenantState, error)
}

// Collector is TenantWatch's poll-driven engine. Each target is one cloud
// tenant ("m365:contoso.onmicrosoft.com" or "gws:contoso.co.id"). Collect asks
// the Source for a read-only posture snapshot and runs the pure check engine
// over it. The reconcile engine then gives open/resolved lifecycle for free: fix
// a finding and the next snapshot no longer produces it, so it auto-resolves.
type Collector struct {
	src   Source
	clock func() time.Time
}

// New builds the collector over a Source.
func New(src Source) *Collector {
	return &Collector{src: src, clock: time.Now}
}

// WithClock overrides the snapshot timestamp source (tests).
func (c *Collector) WithClock(f func() time.Time) *Collector { c.clock = f; return c }

// Describe returns module metadata. Tenant configuration drifts slowly and the
// cloud APIs are rate-limited, so the default interval is generous.
func (c *Collector) Describe() core.ModuleInfo {
	return core.ModuleInfo{
		ID:              ModuleID,
		Name:            "TenantWatch",
		Version:         "0.2.0",
		TargetKind:      "provider:domain (m365:contoso.onmicrosoft.com)",
		DefaultInterval: 12 * time.Hour,
		ResolveAfter:    2, // a transient API hiccup shouldn't flap a finding closed
	}
}

// ValidateTarget parses "provider:domain". Provider must be m365 or gws; domain
// is lower-cased. It does NOT contact the cloud (that happens in Collect) — a
// user adding a tenant gets an instant, offline yes/no on the shape of input.
func (c *Collector) ValidateTarget(raw string) (core.Target, error) {
	raw = strings.TrimSpace(raw)
	provider, domain, ok := SplitCanonical(strings.ToLower(raw))
	if !ok {
		return core.Target{}, &core.IngestError{Field: "target", Reason: `expected "provider:domain", e.g. m365:contoso.onmicrosoft.com or gws:contoso.co.id`}
	}
	switch provider {
	case ProviderM365, ProviderGWS:
	default:
		return core.Target{}, &core.IngestError{Field: "target", Reason: "provider must be m365 or gws, got " + provider}
	}
	if !strings.Contains(domain, ".") {
		return core.Target{}, &core.IngestError{Field: "target", Reason: "domain looks invalid: " + domain}
	}
	canonical := Canonical(provider, domain)
	return core.Target{
		Raw:       raw,
		Canonical: canonical,
		Meta:      map[string]string{"provider": provider, "domain": domain},
	}, nil
}

// Collect snapshots the tenant read-only and evaluates its posture. A snapshot
// error (auth failed, tenant unreachable) is returned as an error — NOT a
// finding — so the scheduler backs off and retries rather than resolving real
// findings on a transient outage.
func (c *Collector) Collect(ctx context.Context, t core.Target) ([]core.Finding, error) {
	provider, domain, ok := SplitCanonical(t.Canonical)
	if !ok {
		return nil, fmt.Errorf("malformed target: %q", t.Canonical)
	}
	state, err := c.src.Snapshot(ctx, provider, domain)
	if err != nil {
		return nil, err
	}
	if state.Provider == "" {
		state.Provider = provider
	}
	if state.Domain == "" {
		state.Domain = domain
	}
	if state.TakenAt.IsZero() {
		state.TakenAt = c.clock()
	}
	return Evaluate(state), nil
}

// Diff defers to the core's fingerprint-based diff.
func (c *Collector) Diff(previous, current []core.Finding) []core.Change { return nil }
