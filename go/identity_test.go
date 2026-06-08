package spiffile

import (
	"crypto/ecdsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testSigningKey loads a provisioned service's private key for signing
// hand-crafted tokens in tests.
func testSigningKey(t *testing.T, root, name string) *ecdsa.PrivateKey {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join(root, servicesDirname, name, DirKeyFilename))
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := parsePrivateKeyPEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

const trustDomain = "example.org"

// fixtures loads conformance/fixtures.json (shared by all implementations).
func fixtures(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "conformance", "fixtures.json"))
	if err != nil {
		t.Fatalf("reading fixtures: %v", err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func fixtureString(t *testing.T, f map[string]json.RawMessage, key string) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(f[key], &s); err != nil {
		t.Fatalf("fixture %s: %v", key, err)
	}
	return s
}

func provisionedRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "identity")
	if err := InitRoot(root, trustDomain); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"orders", "billing"} {
		if _, err := AddService(root, name); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// -- cross-implementation fixtures ------------------------------------------

func TestFixtureJWKMatches(t *testing.T) {
	f := fixtures(t)
	got, err := PublicJWKFromPEM([]byte(fixtureString(t, f, "orders_private_key_pem")))
	if err != nil {
		t.Fatal(err)
	}
	var want JWK
	if err := json.Unmarshal(f["orders_jwk"], &want); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("JWK mismatch:\n got:  %+v\n want: %+v", got, want)
	}
}

func TestFixtureTokenVerifies(t *testing.T) {
	f := fixtures(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), f["bundle"], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "id"), []byte("spiffe://example.org/billing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "key.pem"),
		[]byte(fixtureString(t, f, "billing_private_key_pem")), 0o600); err != nil {
		t.Fatal(err)
	}

	billing, err := FromFiles(filepath.Join(root, "id"), filepath.Join(root, "key.pem"), filepath.Join(root, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	caller, err := billing.Verify(fixtureString(t, f, "token_orders_to_billing_exp_2035"), "", 0)
	if err != nil {
		t.Fatalf("python-minted token must verify: %v", err)
	}
	if caller.ID.String() != "spiffe://example.org/orders" {
		t.Errorf("unexpected caller %q", caller.ID)
	}
}

func TestFixtureMultiAudienceRejected(t *testing.T) {
	// aud is an array containing the right audience — the profile requires
	// a single string, so every implementation must reject it.
	f := fixtures(t)
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "bundle.json"), f["bundle"], 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "id"), []byte("spiffe://example.org/billing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "key.pem"),
		[]byte(fixtureString(t, f, "billing_private_key_pem")), 0o600); err != nil {
		t.Fatal(err)
	}

	billing, err := FromFiles(filepath.Join(root, "id"), filepath.Join(root, "key.pem"), filepath.Join(root, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := billing.Verify(fixtureString(t, f, "token_orders_to_billing_multi_aud_exp_2035"), "", 0); err == nil {
		t.Fatal("multi-audience token must be rejected")
	}
}

func TestFixtureSpiffeIDValidation(t *testing.T) {
	f := fixtures(t)
	var invalid, valid []string
	if err := json.Unmarshal(f["invalid_spiffe_ids"], &invalid); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(f["valid_spiffe_ids"], &valid); err != nil {
		t.Fatal(err)
	}
	for _, id := range invalid {
		if _, err := ParseSpiffeID(id); err == nil {
			t.Errorf("must reject %q", id)
		}
	}
	for _, id := range valid {
		if _, err := ParseSpiffeID(id); err != nil {
			t.Errorf("must accept %q: %v", id, err)
		}
	}
}

// -- behavioral parity with the other implementations ------------------------

func TestRoundtrip(t *testing.T) {
	root := provisionedRoot(t)
	orders, _ := LoadIdentity(root, "orders")
	billing, _ := LoadIdentity(root, "billing")

	token, err := orders.Token(billing.ID.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := billing.Verify(token, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if caller.ID.String() != "spiffe://example.org/orders" {
		t.Errorf("unexpected caller %q", caller.ID)
	}
}

func TestUnverifiedAudience(t *testing.T) {
	root := provisionedRoot(t)
	orders, _ := LoadIdentity(root, "orders")
	billing, _ := LoadIdentity(root, "billing")

	token, err := orders.Token(billing.ID.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	aud, err := UnverifiedAudience(token)
	if err != nil {
		t.Fatal(err)
	}
	if aud != billing.ID.String() {
		t.Errorf("aud = %q, want %q", aud, billing.ID.String())
	}

	if _, err := UnverifiedAudience("not.a.jwt"); err == nil {
		t.Error("expected error for malformed token")
	}

	// A token carrying an array aud must be rejected, not silently coerced.
	arrayAud := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": orders.ID.String(),
		"aud": []string{billing.ID.String(), "spiffe://example.org/other"},
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	signed, err := arrayAud.SignedString(testSigningKey(t, root, "orders"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnverifiedAudience(signed); err == nil {
		t.Error("expected error for array aud")
	}

	// A token with no aud claim returns empty, not an error.
	noAud := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": orders.ID.String(),
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	signed, err = noAud.SignedString(testSigningKey(t, root, "orders"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnverifiedAudience(signed)
	if err != nil || got != "" {
		t.Errorf("missing aud: got %q, err %v; want empty, nil", got, err)
	}
}

func TestWrongAudienceRejected(t *testing.T) {
	root := provisionedRoot(t)
	orders, _ := LoadIdentity(root, "orders")
	billing, _ := LoadIdentity(root, "billing")

	token, _ := orders.Token("spiffe://example.org/someone-else", 0)
	if _, err := billing.Verify(token, "", 0); err == nil {
		t.Fatal("expected rejection for wrong audience")
	}
}

func TestImpersonationRejected(t *testing.T) {
	root := provisionedRoot(t)
	billing, _ := LoadIdentity(root, "billing")

	// orders' key signing sub=billing must not verify.
	forged := &Identity{
		ID:           SpiffeID{TrustDomain: trustDomain, Path: "/billing"},
		keySource:    &fileKeySource{path: filepath.Join(root, "services", "orders", "key.pem")},
		bundleSource: NewFileBundleSource(filepath.Join(root, DirBundleFilename)),
	}
	token, err := forged.Token(billing.ID.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := billing.Verify(token, "", 0); err == nil {
		t.Fatal("expected rejection of impersonated token")
	}
}

func TestUnknownCallerRejected(t *testing.T) {
	otherRoot := filepath.Join(t.TempDir(), "other")
	if err := InitRoot(otherRoot, trustDomain); err != nil {
		t.Fatal(err)
	}
	if _, err := AddService(otherRoot, "intruder"); err != nil {
		t.Fatal(err)
	}
	intruder, _ := LoadIdentity(otherRoot, "intruder")

	root := provisionedRoot(t)
	billing, _ := LoadIdentity(root, "billing")
	token, _ := intruder.Token(billing.ID.String(), 0)
	if _, err := billing.Verify(token, "", 0); err == nil {
		t.Fatal("expected rejection of unknown caller")
	}
}

func TestSigningKeyHotReload(t *testing.T) {
	root := provisionedRoot(t)
	billing, _ := LoadIdentity(root, "billing")
	orders, _ := LoadIdentity(root, "orders") // loaded BEFORE rotation

	if _, err := RotateService(root, "orders", false); err != nil {
		t.Fatal(err)
	}
	// Same Identity object must sign with the NEW key.
	token, err := orders.Token(billing.ID.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := billing.Verify(token, "", 0); err != nil {
		t.Fatalf("token signed after rotation must verify: %v", err)
	}
}

func TestRotationWithOverlap(t *testing.T) {
	root := provisionedRoot(t)
	billing, _ := LoadIdentity(root, "billing")
	orders, _ := LoadIdentity(root, "orders")
	tokenOldKey, _ := orders.Token(billing.ID.String(), time.Minute)

	if _, err := RotateService(root, "orders", true); err != nil {
		t.Fatal(err)
	}
	if _, err := billing.Verify(tokenOldKey, "", 0); err != nil {
		t.Fatalf("old-key token must verify during overlap: %v", err)
	}

	if _, err := RotateService(root, "orders", false); err != nil {
		t.Fatal(err)
	}
	if _, err := billing.Verify(tokenOldKey, "", 0); err == nil {
		t.Fatal("old-key token must be rejected after revocation")
	}
}

func TestRemoveServiceRevokes(t *testing.T) {
	root := provisionedRoot(t)
	billing, _ := LoadIdentity(root, "billing")
	orders, _ := LoadIdentity(root, "orders")
	token, _ := orders.Token(billing.ID.String(), 0)

	if err := RemoveService(root, "orders"); err != nil {
		t.Fatal(err)
	}
	if _, err := billing.Verify(token, "", 0); err == nil {
		t.Fatal("expected rejection after removal")
	}
}

func TestBundleSkipsInvalidEntries(t *testing.T) {
	root := provisionedRoot(t)
	bundlePath := filepath.Join(root, DirBundleFilename)
	var doc map[string]any
	raw, _ := os.ReadFile(bundlePath)
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["identities"].(map[string]any)["spiffe://example.org/bad~path"] = map[string]any{"keys": []any{}}
	out, _ := json.Marshal(doc)
	if err := os.WriteFile(bundlePath, out, 0o644); err != nil {
		t.Fatal(err)
	}

	orders, _ := LoadIdentity(root, "orders")
	billing, _ := LoadIdentity(root, "billing")
	token, _ := orders.Token(billing.ID.String(), 0)
	if _, err := billing.Verify(token, "", 0); err != nil {
		t.Fatalf("one bad entry must not break the rest: %v", err)
	}
}

func TestFromEnv(t *testing.T) {
	root := provisionedRoot(t)
	for key, value := range ServiceEnv(root, "orders") {
		t.Setenv(key, value)
	}
	identity, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if identity.ID.String() != "spiffe://example.org/orders" {
		t.Errorf("unexpected identity %q", identity.ID)
	}
}
