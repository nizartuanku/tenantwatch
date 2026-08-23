// Package dnsauth derives a domain's email-authentication posture (SPF, DKIM,
// DMARC) from its DNS TXT records. It is shared by both cloud providers because
// email authentication lives in DNS, not in the tenant API — the same logic
// serves an M365 and a Google Workspace domain. The resolver is injected so the
// whole thing tests offline.
package dnsauth

import (
	"context"
	"strings"

	"github.com/nizartuanku/tenantwatch/tenant"
)

// Resolver returns the TXT records at a DNS name. net.LookupTXT satisfies this
// after a trivial adapter; tests inject a map.
type Resolver func(ctx context.Context, name string) ([]string, error)

// commonDKIMSelectors are the selectors used by the big providers, checked
// best-effort. A hit proves DKIM; a miss proves nothing (selectors are
// arbitrary), so the check engine treats absence as "not detected", not "broken".
var commonDKIMSelectors = []string{"selector1", "selector2", "google", "k1", "s1", "default", "dkim"}

// EmailAuth resolves SPF, DKIM and DMARC for a domain into one DomainAuth.
func EmailAuth(ctx context.Context, r Resolver, domain string) []tenant.DomainAuth {
	da := tenant.DomainAuth{Domain: domain}

	if txt, err := r(ctx, domain); err == nil {
		for _, rec := range txt {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), "v=spf1") {
				da.SPF = true
				break
			}
		}
	}

	if txt, err := r(ctx, "_dmarc."+domain); err == nil {
		for _, rec := range txt {
			low := strings.ToLower(strings.ReplaceAll(rec, " ", ""))
			if strings.HasPrefix(low, "v=dmarc1") {
				da.DMARCPolicy = dmarcPolicy(low)
				break
			}
		}
	}

	for _, sel := range commonDKIMSelectors {
		if txt, err := r(ctx, sel+"._domainkey."+domain); err == nil && hasDKIM(txt) {
			da.DKIM = true
			break
		}
	}

	return []tenant.DomainAuth{da}
}

func dmarcPolicy(low string) string {
	// low is space-stripped, e.g. "v=dmarc1;p=none;rua=..."
	for _, part := range strings.Split(low, ";") {
		if strings.HasPrefix(part, "p=") {
			switch strings.TrimPrefix(part, "p=") {
			case "reject":
				return "reject"
			case "quarantine":
				return "quarantine"
			default:
				return "none"
			}
		}
	}
	return "none" // record present but no explicit policy → treated as none
}

func hasDKIM(txt []string) bool {
	for _, rec := range txt {
		low := strings.ToLower(rec)
		if strings.Contains(low, "v=dkim1") || strings.Contains(low, "k=rsa") || strings.Contains(low, "p=") {
			return true
		}
	}
	return false
}
