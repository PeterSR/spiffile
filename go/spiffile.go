// Package spiffile implements the spiffile profile primitives: EC P-256
// keypairs, public JWKs with RFC 7638 thumbprints, and trust bundle
// documents. See PROFILE.md at the repository root.
package spiffile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
)

// BundleVersion is the spiffile bundle document version this package writes.
const BundleVersion = 1

// JWTSVIDUse is the SPIFFE-standard "use" value for JWT-SVID keys.
const JWTSVIDUse = "jwt-svid"

// Algorithm is the profile v0 signature algorithm.
const Algorithm = "ES256"

const coordLength = 32 // P-256 coordinate length in bytes

// JWK is a public EC key in JWK form, as embedded in trust bundles.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// GeneratePrivateKeyPEM generates an EC P-256 key, PEM-encoded PKCS#8.
func GeneratePrivateKeyPEM() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// PublicJWKFromPEM derives the public JWK (with thumbprint kid) from a
// PEM-encoded PKCS#8 private key.
func PublicJWKFromPEM(pemBytes []byte) (JWK, error) {
	_, jwk, err := parsePrivateKeyPEM(pemBytes)
	return jwk, err
}

// parsePrivateKeyPEM parses a PKCS#8 EC P-256 private key and derives its
// public JWK.
func parsePrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, JWK, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, JWK{}, fmt.Errorf("no PEM block found")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, JWK{}, fmt.Errorf("parsing key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, JWK{}, fmt.Errorf("expected an EC P-256 private key")
	}

	jwk := JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, coordLength))),
		Y:   base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, coordLength))),
		Use: JWTSVIDUse,
		Alg: Algorithm,
	}
	jwk.Kid = thumbprint(jwk)
	return key, jwk, nil
}

// thumbprint computes the RFC 7638 JWK thumbprint (SHA-256, base64url).
func thumbprint(jwk JWK) string {
	required := map[string]string{"crv": jwk.Crv, "kty": jwk.Kty, "x": jwk.X, "y": jwk.Y}
	keys := make([]string, 0, len(required))
	for k := range required {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	canonical := "{"
	for i, k := range keys {
		if i > 0 {
			canonical += ","
		}
		canonical += fmt.Sprintf("%q:%q", k, required[k])
	}
	canonical += "}"
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Bundle is the spiffile trust bundle document.
type Bundle struct {
	TrustDomain     string            `json:"trust_domain"`
	SpiffileVersion int               `json:"spiffile_version"`
	Identities      map[string]KeySet `json:"identities"`
}

// KeySet is the JWKS bound to one identity.
type KeySet struct {
	Keys []json.RawMessage `json:"keys"`
}

// MarshalBundle renders a bundle document deterministically.
func MarshalBundle(b Bundle) ([]byte, error) {
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
