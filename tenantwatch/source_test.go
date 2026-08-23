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
	"strings"
	"testing"
	"time"
)

func TestLoadCredsMissingFileIsEmpty(t *testing.T) {
	c, err := LoadCreds("/no/such/file.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.M365) != 0 || len(c.GWS) != 0 {
		t.Errorf("missing creds file should yield empty creds")
	}
}

func TestSnapshotUnknownTenantErrors(t *testing.T) {
	m := New(&Creds{})
	if _, err := m.Snapshot(context.Background(), "m365", "nobody.com"); err == nil {
		t.Fatal("snapshot for a tenant with no credentials must error, not return empty state")
	}
}

// The Google service-account JWT is the trickiest live-auth path; prove it
// produces a correctly-signed RS256 assertion with the right claims, offline.
func TestSignGoogleJWT(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	sa := saKey{ClientEmail: "svc@proj.iam.gserviceaccount.com", PrivateKey: string(pemBytes)}
	now := time.Unix(1_700_000_000, 0)
	assertion, err := signGoogleJWT(sa, "admin@contoso.co.id", now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		t.Fatalf("assertion must have 3 parts, got %d", len(parts))
	}
	// Verify the signature over header.payload.
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, h[:], sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	// Claims.
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != sa.ClientEmail {
		t.Errorf("iss = %v", claims["iss"])
	}
	if claims["sub"] != "admin@contoso.co.id" {
		t.Errorf("sub = %v (domain-wide delegation must impersonate the admin)", claims["sub"])
	}
	if s, _ := claims["scope"].(string); !strings.Contains(s, "admin.directory.user.readonly") {
		t.Errorf("scope must be read-only directory: %v", claims["scope"])
	}
	if claims["aud"] != "https://oauth2.googleapis.com/token" {
		t.Errorf("aud = %v", claims["aud"])
	}
}
