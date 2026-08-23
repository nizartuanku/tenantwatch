package tenantwatch

import (
	"context"
	"net"
)

// NetResolver is the production dnsauth.Resolver: it looks up TXT records via
// the system resolver. Air-gapped deployments that cannot resolve public DNS
// simply get no email-authentication findings (the provider skips the area).
func NetResolver(ctx context.Context, name string) ([]string, error) {
	var r net.Resolver
	return r.LookupTXT(ctx, name)
}
