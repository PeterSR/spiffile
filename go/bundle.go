package spiffile

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
)

// ErrUnknownIdentity is wrapped by KeysFor when the claimed identity has no
// keys in the trust bundle.
var ErrUnknownIdentity = fmt.Errorf("identity has no keys in trust bundle")

// ParseBundle parses and validates a trust bundle document.
//
// A malformed entry must not take down verification for everyone else in
// the bundle: invalid entries are skipped and reported as warnings rather
// than failing the parse — same semantics as every other spiffile
// implementation. Top-level malformation (missing members, wrong version)
// still fails.
func ParseBundle(doc []byte) (Bundle, []string, error) {
	var raw struct {
		TrustDomain     *string                    `json:"trust_domain"`
		SpiffileVersion *int                       `json:"spiffile_version"`
		Identities      map[string]json.RawMessage `json:"identities"`
	}
	if err := json.Unmarshal(doc, &raw); err != nil {
		return Bundle{}, nil, fmt.Errorf("bundle is not valid JSON: %w", err)
	}
	if raw.TrustDomain == nil || raw.SpiffileVersion == nil || raw.Identities == nil {
		return Bundle{}, nil, fmt.Errorf("bundle is missing a required member (trust_domain, spiffile_version, identities)")
	}
	if *raw.SpiffileVersion != BundleVersion {
		return Bundle{}, nil, fmt.Errorf("unsupported spiffile_version: %d", *raw.SpiffileVersion)
	}

	bundle := Bundle{
		TrustDomain:     *raw.TrustDomain,
		SpiffileVersion: *raw.SpiffileVersion,
		Identities:      map[string]KeySet{},
	}
	var warnings []string
	for rawID, rawKeys := range raw.Identities {
		id, err := ParseSpiffeID(rawID)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skipping invalid bundle entry %q: %v", rawID, err))
			continue
		}
		if id.TrustDomain != bundle.TrustDomain {
			warnings = append(warnings, fmt.Sprintf("skipping bundle entry %q: not in trust domain %q", rawID, bundle.TrustDomain))
			continue
		}
		var keySet KeySet
		if err := json.Unmarshal(rawKeys, &keySet); err != nil || len(keySet.Keys) == 0 {
			warnings = append(warnings, fmt.Sprintf("skipping bundle entry %q: no keys", rawID))
			continue
		}
		bundle.Identities[id.String()] = keySet
	}
	return bundle, warnings, nil
}

// KeysFor returns the JWKs bound to one identity.
func (b Bundle) KeysFor(spiffeID string) ([]json.RawMessage, error) {
	keySet, ok := b.Identities[spiffeID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownIdentity, spiffeID)
	}
	return keySet.Keys, nil
}

// FileBundleSource reads a bundle from a file, hot-reloading when the file
// changes (mtime+size), so secret-sync style updates are picked up without
// restarts. Parse warnings are logged via slog once per reload.
type FileBundleSource struct {
	path string

	mu     sync.Mutex
	mtime  int64
	size   int64
	bundle *Bundle
}

// NewFileBundleSource creates a source for the bundle at path.
func NewFileBundleSource(path string) *FileBundleSource {
	return &FileBundleSource{path: path}
}

// Get returns the current bundle, re-reading the file if it changed.
func (s *FileBundleSource) Get() (Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	info, err := os.Stat(s.path)
	if err != nil {
		return Bundle{}, fmt.Errorf("cannot stat bundle at %s: %w", s.path, err)
	}
	if s.bundle != nil && info.ModTime().UnixNano() == s.mtime && info.Size() == s.size {
		return *s.bundle, nil
	}

	doc, err := os.ReadFile(s.path)
	if err != nil {
		return Bundle{}, fmt.Errorf("cannot read bundle at %s: %w", s.path, err)
	}
	bundle, warnings, err := ParseBundle(doc)
	if err != nil {
		return Bundle{}, fmt.Errorf("cannot parse bundle at %s: %w", s.path, err)
	}
	for _, w := range warnings {
		slog.Warn("spiffile bundle", "warning", w, "path", s.path)
	}
	s.bundle = &bundle
	s.mtime = info.ModTime().UnixNano()
	s.size = info.Size()
	return bundle, nil
}
