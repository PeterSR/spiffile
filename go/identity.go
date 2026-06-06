package spiffile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Defaults shared by all spiffile implementations.
const (
	DefaultTTL    = 60 * time.Second
	DefaultLeeway = 30 * time.Second
)

// Environment configuration, shared by all spiffile implementations.
const (
	EnvDir        = "SPIFFILE_DIR"
	EnvIDFile     = "SPIFFILE_ID_FILE"
	EnvKeyFile    = "SPIFFILE_KEY_FILE"
	EnvBundleFile = "SPIFFILE_BUNDLE_FILE"

	DirIDFilename     = "id"
	DirKeyFilename    = "key.pem"
	DirBundleFilename = "bundle.json"
)

// Caller is the verified peer of an inbound request.
type Caller struct {
	ID     SpiffeID
	Claims jwt.MapClaims
}

// fileKeySource reads the private key from a file, hot-reloading when it
// changes. Key rotation replaces the key file; signing must pick the new key
// up without a process restart — otherwise tokens break once the rotated-out
// public key is pruned from peers' bundles.
type fileKeySource struct {
	path string

	mu    sync.Mutex
	mtime int64
	size  int64
	key   *ecdsa.PrivateKey
	kid   string
}

func (s *fileKeySource) get() (*ecdsa.PrivateKey, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	info, err := os.Stat(s.path)
	if err != nil {
		return nil, "", fmt.Errorf("cannot stat key at %s: %w", s.path, err)
	}
	if s.key == nil || info.ModTime().UnixNano() != s.mtime || info.Size() != s.size {
		pemBytes, err := os.ReadFile(s.path)
		if err != nil {
			return nil, "", fmt.Errorf("cannot read key at %s: %w", s.path, err)
		}
		key, jwk, err := parsePrivateKeyPEM(pemBytes)
		if err != nil {
			return nil, "", fmt.Errorf("cannot parse key at %s: %w", s.path, err)
		}
		s.key = key
		s.kid = jwk.Kid
		s.mtime = info.ModTime().UnixNano()
		s.size = info.Size()
	}
	return s.key, s.kid, nil
}

// Identity is a service's own identity plus the trust bundle to verify
// peers against.
type Identity struct {
	ID SpiffeID

	keySource    *fileKeySource
	bundleSource *FileBundleSource
}

// FromFiles loads an identity from the three profile files.
func FromFiles(idFile, keyFile, bundleFile string) (*Identity, error) {
	raw, err := os.ReadFile(idFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read identity file: %w", err)
	}
	id, err := ParseSpiffeID(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, err
	}
	identity := &Identity{
		ID:           id,
		keySource:    &fileKeySource{path: keyFile},
		bundleSource: NewFileBundleSource(bundleFile),
	}
	if _, _, err := identity.keySource.get(); err != nil {
		return nil, err
	}
	return identity, nil
}

// FromEnv loads an identity from environment configuration: either
// SPIFFILE_DIR (containing id / key.pem / bundle.json) or the three explicit
// file variables, which take precedence per variable.
func FromEnv() (*Identity, error) {
	dir := os.Getenv(EnvDir)
	idFile := os.Getenv(EnvIDFile)
	keyFile := os.Getenv(EnvKeyFile)
	bundleFile := os.Getenv(EnvBundleFile)
	if dir != "" {
		if idFile == "" {
			idFile = filepath.Join(dir, DirIDFilename)
		}
		if keyFile == "" {
			keyFile = filepath.Join(dir, DirKeyFilename)
		}
		if bundleFile == "" {
			bundleFile = filepath.Join(dir, DirBundleFilename)
		}
	}
	if idFile == "" || keyFile == "" || bundleFile == "" {
		return nil, fmt.Errorf("identity not configured: set %s, or %s + %s + %s",
			EnvDir, EnvIDFile, EnvKeyFile, EnvBundleFile)
	}
	return FromFiles(idFile, keyFile, bundleFile)
}

// Token mints a JWT-SVID for a single target audience.
func (i *Identity) Token(audience string, ttl time.Duration) (string, error) {
	audienceID, err := ParseSpiffeID(audience)
	if err != nil {
		return "", fmt.Errorf("invalid audience: %w", err)
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	key, kid, err := i.keySource.get()
	if err != nil {
		return "", err
	}
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": i.ID.String(),
		"aud": audienceID.String(),
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
	})
	token.Header["kid"] = kid
	return token.SignedString(key)
}

// Verify verifies an inbound JWT-SVID and returns the verified caller.
// An empty audience defaults to this identity's own SPIFFE ID.
func (i *Identity) Verify(tokenString, audience string, leeway time.Duration) (Caller, error) {
	expectedAudience := audience
	if expectedAudience == "" {
		expectedAudience = i.ID.String()
	}
	if leeway <= 0 {
		leeway = DefaultLeeway
	}

	// Read the claimed identity (unverified) to scope the key lookup —
	// the security pivot of the profile: only keys bound to the claimed
	// identity in the bundle may validate it.
	unverified, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return Caller{}, fmt.Errorf("malformed token: %w", err)
	}
	claimedSub, err := unverified.Claims.GetSubject()
	if err != nil || claimedSub == "" {
		return Caller{}, fmt.Errorf("token has no sub claim")
	}
	claimedID, err := ParseSpiffeID(claimedSub)
	if err != nil {
		return Caller{}, fmt.Errorf("token sub is not a SPIFFE ID: %w", err)
	}

	// The profile requires aud to be a single string. golang-jwt would
	// happily match the expected audience inside an array, so reject
	// non-string aud claims here.
	if aud, present := unverified.Claims.(jwt.MapClaims)["aud"]; present {
		if _, isString := aud.(string); !isString {
			return Caller{}, fmt.Errorf("token rejected: aud must be a single string audience")
		}
	}

	bundle, err := i.bundleSource.Get()
	if err != nil {
		return Caller{}, err
	}
	boundJWKs, err := bundle.KeysFor(claimedID.String())
	if err != nil {
		return Caller{}, err
	}

	kid, _ := unverified.Header["kid"].(string)
	candidates := candidateKeys(boundJWKs, kid)
	if len(candidates) == 0 {
		return Caller{}, fmt.Errorf("no usable keys bound to %q", claimedSub)
	}

	var lastErr error
	for _, publicKey := range candidates {
		claims := jwt.MapClaims{}
		_, err := jwt.NewParser(
			jwt.WithValidMethods([]string{Algorithm}),
			jwt.WithAudience(expectedAudience),
			jwt.WithLeeway(leeway),
			jwt.WithExpirationRequired(),
		).ParseWithClaims(tokenString, claims, func(*jwt.Token) (any, error) {
			return publicKey, nil
		})
		if err == nil {
			return Caller{ID: claimedID, Claims: claims}, nil
		}
		lastErr = err
		if !strings.Contains(err.Error(), "signature is invalid") {
			// Signature was fine but a claim failed — no other key will fix that.
			return Caller{}, fmt.Errorf("token rejected: %w", err)
		}
	}
	return Caller{}, fmt.Errorf("signature does not match any key bound to %q: %w", claimedSub, lastErr)
}

// candidateKeys parses the JWKs bound to an identity into public keys,
// preferring an exact kid match and falling back to all bound keys.
func candidateKeys(jwks []json.RawMessage, kid string) []*ecdsa.PublicKey {
	var matched, all []*ecdsa.PublicKey
	for _, raw := range jwks {
		var jwk JWK
		if err := json.Unmarshal(raw, &jwk); err != nil {
			continue
		}
		publicKey, err := jwkToPublicKey(jwk)
		if err != nil {
			continue
		}
		all = append(all, publicKey)
		if kid != "" && jwk.Kid == kid {
			matched = append(matched, publicKey)
		}
	}
	if len(matched) > 0 {
		return matched
	}
	return all
}

func jwkToPublicKey(jwk JWK) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported key type %s/%s", jwk.Kty, jwk.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}
