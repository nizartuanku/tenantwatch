// Package tenant holds TenantWatch's intelligence: a provider-neutral snapshot
// of a cloud workspace's security posture (TenantState) and the pure check
// engine that turns it into findings. Nothing here talks to Microsoft or Google
// — that lives in the graph/ and gws/ providers, which fill a TenantState this
// package reasons about. Keeping the checks pure makes the product's judgement
// exhaustively testable offline: feed a TenantState, assert the findings.
package tenant

import "time"

// Provider identifies which cloud a snapshot came from.
const (
	ProviderM365 = "m365"
	ProviderGWS  = "gws"
)

// TenantState is the normalised, provider-neutral posture snapshot. Both the
// Microsoft Graph and the Google Workspace providers map their very different
// APIs onto this one shape, so a single check engine serves both clouds.
//
// A provider fills only what it could read. Anything it could not assess goes
// in Notes as an honest "manual review" line rather than being silently treated
// as "fine" — a security tool that hides its blind spots is worse than useless.
type TenantState struct {
	Provider string    // "m365" | "gws"
	Domain   string    // primary domain, e.g. "contoso.onmicrosoft.com"
	TakenAt  time.Time // when the snapshot was captured

	Users   []User
	Grants  []OAuthGrant
	Domains []DomainAuth
	Sharing SharingConfig

	// LegacyAuthEnabled is true when basic/legacy authentication protocols
	// (IMAP/POP/SMTP AUTH, or M365 legacy auth) are still permitted tenant-wide.
	LegacyAuthEnabled bool
	// ConditionalAccess is true when at least one enforced conditional-access /
	// context-aware access policy exists. Nil-equivalent (false) with a Note
	// when the provider could not read it.
	ConditionalAccess bool

	// Assessed lists the areas this snapshot actually covered, so a check for an
	// area the provider skipped stays silent instead of firing a false "all
	// clear" or a false alarm. Keyed by area constants below.
	Assessed map[string]bool

	// Notes are honest "could not assess X — review manually" lines surfaced to
	// the user as Info findings. Never used to fabricate certainty.
	Notes []string
}

// Assessment areas — a provider marks the ones it managed to read.
const (
	AreaMFA          = "mfa"
	AreaLegacyAuth   = "legacy_auth"
	AreaOAuth        = "oauth"
	AreaAdminRoles   = "admin_roles"
	AreaSharing      = "sharing"
	AreaMailForward  = "mail_forward"
	AreaEmailAuth    = "email_auth"
	AreaConditional  = "conditional_access"
	AreaInactiveUser = "inactive_user"
)

// User is one account in the tenant, normalised across clouds.
type User struct {
	ID          string
	Email       string
	DisplayName string
	Enabled     bool

	IsAdmin    bool
	AdminRoles []string // e.g. ["Global Administrator"]

	MFAEnabled bool

	// LastActive is the last sign-in time the provider reported; zero when
	// unknown (the inactive-user check ignores zero rather than guessing).
	LastActive time.Time

	// ExternalForwarding is set when the mailbox auto-forwards to an address
	// outside the tenant's domains — a classic BEC/exfil signal.
	ExternalForwarding bool
	ForwardTarget      string
}

// OAuthGrant is a third-party application granted access to tenant data.
type OAuthGrant struct {
	AppID       string
	AppName     string
	Scopes      []string
	ConsentType string // "AllPrincipals" (admin, org-wide) | "Principal" (single user)
	Publisher   string // may be empty / "unverified"
}

// DomainAuth is one domain's email-authentication posture.
type DomainAuth struct {
	Domain string
	SPF    bool
	DKIM   bool
	// DMARCPolicy is the p= value: "none" | "quarantine" | "reject", or "" when
	// no DMARC record exists at all.
	DMARCPolicy string
}

// SharingConfig captures external file-sharing exposure.
type SharingConfig struct {
	// AnyoneLinks is true when "anyone with the link" (unauthenticated) sharing
	// is permitted — the broadest exposure.
	AnyoneLinks bool
	// ExternalSharing is true when sharing with people outside the org is on
	// (guest access). Less severe than AnyoneLinks but worth surfacing.
	ExternalSharing bool
	// Level is the provider's own label for the sharing tier, for evidence.
	Level string
}

// riskyOAuthScopes are scope substrings that grant broad read/write to mail or
// files — the ones that turn an over-permissioned third-party app into a data
// exfiltration path. Matching is substring + case-insensitive so both Graph
// (Mail.ReadWrite) and Google (https://www.googleapis.com/auth/gmail.modify)
// scope vocabularies are covered by one list.
var riskyOAuthScopes = []string{
	"mail.read", "mail.readwrite", "mail.send",
	"files.read", "files.readwrite",
	"gmail.", "drive", "spreadsheets", "documents",
	"full_access", "directory.readwrite", "user.readwrite",
}
