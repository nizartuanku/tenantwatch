// Package tenantwatch wires TenantWatch's live data sources: it loads tenant
// credentials, routes each scan target to the right cloud provider (Microsoft
// Graph or Google Workspace), and implements the token acquisition each cloud
// needs (M365 client-credentials, Google service-account JWT). The pure check
// engine and the providers' response mapping live elsewhere and are fully
// tested; this package is the thin, credential-handling live edge.
package tenantwatch

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nizartuanku/tenantwatch/dnsauth"
	"github.com/nizartuanku/tenantwatch/graph"
	"github.com/nizartuanku/tenantwatch/gws"
	"github.com/nizartuanku/tenantwatch/tenant"
)

// Creds is the on-disk credential file: which tenants TenantWatch may read and
// how to authenticate to each. It never leaves the host; TenantWatch reads only
// the tenants listed here, read-only.
type Creds struct {
	M365 []M365Creds `json:"m365"`
	GWS  []GWSCreds  `json:"gws"`
}

// M365Creds authenticates an app registration (client-credentials flow) that has
// been granted read-only Graph application permissions in the tenant.
type M365Creds struct {
	Domain       string `json:"domain"`
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// GWSCreds authenticates a service account with domain-wide delegation,
// impersonating a read-only admin.
type GWSCreds struct {
	Domain             string `json:"domain"`
	AdminEmail         string `json:"admin_email"`          // the admin to impersonate
	ServiceAccountJSON string `json:"service_account_json"` // path to the SA key file
}

// LoadCreds reads and parses a credentials file. A missing file is not fatal —
// the product runs and simply reports "no credentials for <tenant>" when a scan
// is attempted, so the dashboard is reachable before setup is complete.
func LoadCreds(path string) (*Creds, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Creds{}, nil
		}
		return nil, err
	}
	var c Creds
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// MultiSource implements tenant.Source by routing a target to the provider that
// owns its domain, building that provider with live token+fetch on demand.
type MultiSource struct {
	Creds *Creds
	DNS   dnsauth.Resolver
	// HTTP is injected in tests; nil uses a real client.
	HTTP *http.Client

	mu   sync.Mutex
	toks map[string]cachedToken
}

type cachedToken struct {
	token   string
	expires time.Time
}

// New builds a MultiSource with a real HTTP client and DNS resolver.
func New(creds *Creds) *MultiSource {
	return &MultiSource{
		Creds: creds,
		DNS:   NetResolver,
		HTTP:  &http.Client{Timeout: 30 * time.Second},
		toks:  map[string]cachedToken{},
	}
}

// Snapshot routes to the right provider and returns its posture snapshot.
func (m *MultiSource) Snapshot(ctx context.Context, provider, domain string) (tenant.TenantState, error) {
	switch provider {
	case tenant.ProviderM365:
		c, ok := m.m365For(domain)
		if !ok {
			return tenant.TenantState{}, fmt.Errorf("no M365 credentials configured for %s — add it to the creds file (see INSTALL)", domain)
		}
		gp := &graph.Provider{
			DNS:   m.DNS,
			Fetch: m.fetch,
			Token: func(ctx context.Context) (string, error) { return m.m365Token(ctx, c) },
		}
		return gp.Snapshot(ctx, domain)
	case tenant.ProviderGWS:
		c, ok := m.gwsFor(domain)
		if !ok {
			return tenant.TenantState{}, fmt.Errorf("no Google Workspace credentials configured for %s — add it to the creds file (see INSTALL)", domain)
		}
		gp := &gws.Provider{
			DNS:   m.DNS,
			Fetch: m.fetch,
			Token: func(ctx context.Context) (string, error) { return m.gwsToken(ctx, c) },
		}
		return gp.Snapshot(ctx, domain)
	default:
		return tenant.TenantState{}, fmt.Errorf("unknown provider %q", provider)
	}
}

func (m *MultiSource) m365For(domain string) (M365Creds, bool) {
	for _, c := range m.Creds.M365 {
		if strings.EqualFold(c.Domain, domain) {
			return c, true
		}
	}
	return M365Creds{}, false
}

func (m *MultiSource) gwsFor(domain string) (GWSCreds, bool) {
	for _, c := range m.Creds.GWS {
		if strings.EqualFold(c.Domain, domain) {
			return c, true
		}
	}
	return GWSCreds{}, false
}

// fetch is the shared bearer GET used by both providers.
func (m *MultiSource) fetch(ctx context.Context, u, bearer string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	resp, err := m.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GET %s: %s: %s", u, resp.Status, snippet(body))
	}
	return body, nil
}

func (m *MultiSource) client() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	return http.DefaultClient
}

// --- M365 token (client credentials) ----------------------------------------

func (m *MultiSource) m365Token(ctx context.Context, c M365Creds) (string, error) {
	key := "m365:" + c.TenantID + ":" + c.ClientID
	if t, ok := m.cached(key); ok {
		return t, nil
	}
	endpoint := "https://login.microsoftonline.com/" + c.TenantID + "/oauth2/v2.0/token"
	form := url.Values{
		"client_id":     {c.ClientID},
		"client_secret": {c.ClientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}
	tok, exp, err := m.postToken(ctx, endpoint, form)
	if err != nil {
		return "", err
	}
	m.store(key, tok, exp)
	return tok, nil
}

// --- Google Workspace token (service-account JWT) ---------------------------

type saKey struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

func (m *MultiSource) gwsToken(ctx context.Context, c GWSCreds) (string, error) {
	key := "gws:" + c.Domain + ":" + c.AdminEmail
	if t, ok := m.cached(key); ok {
		return t, nil
	}
	raw, err := os.ReadFile(c.ServiceAccountJSON)
	if err != nil {
		return "", fmt.Errorf("read service account json: %w", err)
	}
	var sa saKey
	if err := json.Unmarshal(raw, &sa); err != nil {
		return "", fmt.Errorf("parse service account json: %w", err)
	}
	assertion, err := signGoogleJWT(sa, c.AdminEmail, m.now())
	if err != nil {
		return "", err
	}
	endpoint := sa.TokenURI
	if endpoint == "" {
		endpoint = "https://oauth2.googleapis.com/token"
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	tok, exp, err := m.postToken(ctx, endpoint, form)
	if err != nil {
		return "", err
	}
	m.store(key, tok, exp)
	return tok, nil
}

// signGoogleJWT builds and signs the RS256 assertion for domain-wide delegation,
// impersonating adminEmail with the read-only Admin SDK scope.
func signGoogleJWT(sa saKey, adminEmail string, now time.Time) (string, error) {
	priv, err := parseRSAKey(sa.PrivateKey)
	if err != nil {
		return "", err
	}
	header := base64url([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := map[string]any{
		"iss":   sa.ClientEmail,
		"sub":   adminEmail,
		"scope": "https://www.googleapis.com/auth/admin.directory.user.readonly",
		"aud":   "https://oauth2.googleapis.com/token",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := header + "." + base64url(cb)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64url(sig), nil
}

func parseRSAKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("service account private_key is not valid PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, fmt.Errorf("service account key is not RSA")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// --- shared token plumbing --------------------------------------------------

func (m *MultiSource) postToken(ctx context.Context, endpoint string, form url.Values) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := m.client().Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return "", time.Time{}, fmt.Errorf("token endpoint %s: %s: %s", endpoint, resp.Status, snippet(body))
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", time.Time{}, err
	}
	if tr.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("token endpoint returned no access_token")
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	return tr.AccessToken, m.now().Add(ttl), nil
}

func (m *MultiSource) cached(key string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.toks[key]
	if !ok || m.now().After(e.expires.Add(-2*time.Minute)) {
		return "", false
	}
	return e.token, true
}

func (m *MultiSource) store(key, tok string, exp time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.toks == nil {
		m.toks = map[string]cachedToken{}
	}
	m.toks[key] = cachedToken{token: tok, expires: exp}
}

func (m *MultiSource) now() time.Time { return time.Now() }

func base64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}
