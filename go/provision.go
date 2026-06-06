package spiffile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Provisioning primitives: create, rotate and revoke identities.
//
// These functions are the building blocks for producers — provisioning
// scripts, development tooling, operators. They generate keypairs and
// maintain the trust bundle; consumers only ever read the resulting files.
//
// A provisioned root directory looks like:
//
//	<root>/
//	  bundle.json                # the trust bundle (distribute to everyone)
//	  services/<name>/id         # the service's SPIFFE ID
//	  services/<name>/key.pem    # the service's private key (deliver only to it)

const (
	servicesDirname = "services"
)

// InitRoot creates an empty provisioning root with an empty bundle.
func InitRoot(root, trustDomain string) error {
	bundlePath := filepath.Join(root, DirBundleFilename)
	if _, err := os.Stat(bundlePath); err == nil {
		return fmt.Errorf("already initialized: %s", bundlePath)
	}
	if err := os.MkdirAll(filepath.Join(root, servicesDirname), 0o755); err != nil {
		return err
	}
	return writeBundle(bundlePath, Bundle{
		TrustDomain:     trustDomain,
		SpiffileVersion: BundleVersion,
		Identities:      map[string]KeySet{},
	})
}

// AddService generates a keypair for a service and registers its public key
// in the bundle. Idempotent: a service that already has a key keeps it.
func AddService(root, name string) (SpiffeID, error) {
	bundle, err := readBundle(root)
	if err != nil {
		return SpiffeID{}, err
	}
	id, err := ParseSpiffeID(fmt.Sprintf("spiffe://%s/%s", bundle.TrustDomain, name))
	if err != nil {
		return SpiffeID{}, err
	}

	serviceDir := filepath.Join(root, servicesDirname, name)
	keyPath := filepath.Join(serviceDir, DirKeyFilename)
	if _, err := os.Stat(keyPath); err == nil {
		return id, nil
	}

	if err := os.MkdirAll(serviceDir, 0o755); err != nil {
		return SpiffeID{}, err
	}
	pemBytes, err := GeneratePrivateKeyPEM()
	if err != nil {
		return SpiffeID{}, err
	}
	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		return SpiffeID{}, err
	}
	if err := os.WriteFile(filepath.Join(serviceDir, DirIDFilename), []byte(id.String()+"\n"), 0o644); err != nil {
		return SpiffeID{}, err
	}

	jwk, err := PublicJWKFromPEM(pemBytes)
	if err != nil {
		return SpiffeID{}, err
	}
	return id, setKeys(root, bundle, id.String(), []JWK{jwk})
}

// RotateService generates a new keypair for a service. With keepOld the
// previous public key stays in the bundle so in-flight tokens and stale
// bundle copies keep working.
func RotateService(root, name string, keepOld bool) (SpiffeID, error) {
	bundle, err := readBundle(root)
	if err != nil {
		return SpiffeID{}, err
	}
	id, err := ParseSpiffeID(fmt.Sprintf("spiffe://%s/%s", bundle.TrustDomain, name))
	if err != nil {
		return SpiffeID{}, err
	}

	keyPath := filepath.Join(root, servicesDirname, name, DirKeyFilename)
	if _, err := os.Stat(keyPath); err != nil {
		return SpiffeID{}, fmt.Errorf("unknown service %q: %w", name, err)
	}

	pemBytes, err := GeneratePrivateKeyPEM()
	if err != nil {
		return SpiffeID{}, err
	}
	newJWK, err := PublicJWKFromPEM(pemBytes)
	if err != nil {
		return SpiffeID{}, err
	}

	keys := []JWK{newJWK}
	if keepOld {
		for _, raw := range bundle.Identities[id.String()].Keys {
			var jwk JWK
			if err := json.Unmarshal(raw, &jwk); err == nil && jwk.Kid != newJWK.Kid {
				keys = append(keys, jwk)
			}
		}
	}

	if err := os.WriteFile(keyPath, pemBytes, 0o600); err != nil {
		return SpiffeID{}, err
	}
	return id, setKeys(root, bundle, id.String(), keys)
}

// RemoveService removes a service's keys from the bundle (revocation) and
// deletes its directory.
func RemoveService(root, name string) error {
	bundle, err := readBundle(root)
	if err != nil {
		return err
	}
	delete(bundle.Identities, fmt.Sprintf("spiffe://%s/%s", bundle.TrustDomain, name))
	if err := writeBundle(filepath.Join(root, DirBundleFilename), bundle); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(root, servicesDirname, name))
}

// ServiceEnv returns the environment variables that point a consumer at its
// identity files.
func ServiceEnv(root, name string) map[string]string {
	serviceDir := filepath.Join(root, servicesDirname, name)
	return map[string]string{
		EnvIDFile:     filepath.Join(serviceDir, DirIDFilename),
		EnvKeyFile:    filepath.Join(serviceDir, DirKeyFilename),
		EnvBundleFile: filepath.Join(root, DirBundleFilename),
	}
}

// LoadIdentity loads a provisioned service's Identity directly (tests, tooling).
func LoadIdentity(root, name string) (*Identity, error) {
	env := ServiceEnv(root, name)
	return FromFiles(env[EnvIDFile], env[EnvKeyFile], env[EnvBundleFile])
}

func readBundle(root string) (Bundle, error) {
	return NewFileBundleSource(filepath.Join(root, DirBundleFilename)).Get()
}

func setKeys(root string, bundle Bundle, spiffeID string, jwks []JWK) error {
	keys := make([]json.RawMessage, 0, len(jwks))
	for _, jwk := range jwks {
		raw, err := json.Marshal(jwk)
		if err != nil {
			return err
		}
		keys = append(keys, raw)
	}
	bundle.Identities[spiffeID] = KeySet{Keys: keys}
	return writeBundle(filepath.Join(root, DirBundleFilename), bundle)
}

func writeBundle(path string, bundle Bundle) error {
	doc, err := MarshalBundle(bundle)
	if err != nil {
		return err
	}
	return os.WriteFile(path, doc, 0o644)
}
