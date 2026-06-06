package spiffile

import (
	"fmt"
	"strings"
)

// SpiffeID is a validated SPIFFE ID, e.g. spiffe://example.org/billing.
type SpiffeID struct {
	TrustDomain string
	Path        string // empty, or starts with "/"
}

const scheme = "spiffe://"

// ParseSpiffeID validates a SPIFFE ID string. The rules are identical across
// all spiffile implementations (see the cross-implementation fixtures).
func ParseSpiffeID(value string) (SpiffeID, error) {
	if !strings.HasPrefix(value, scheme) {
		return SpiffeID{}, fmt.Errorf("not a SPIFFE ID (missing %q scheme): %q", scheme, value)
	}
	rest := value[len(scheme):]
	trustDomain, path, hasPath := strings.Cut(rest, "/")

	if trustDomain == "" {
		return SpiffeID{}, fmt.Errorf("empty trust domain: %q", value)
	}
	for _, r := range trustDomain {
		if !isTrustDomainChar(r) {
			return SpiffeID{}, fmt.Errorf(
				"trust domain may only contain lowercase letters, digits, '.', '_' and '-': %q", value)
		}
	}

	if hasPath {
		if path == "" {
			return SpiffeID{}, fmt.Errorf("trailing slash is not allowed: %q", value)
		}
		for _, segment := range strings.Split(path, "/") {
			if segment == "" {
				return SpiffeID{}, fmt.Errorf("empty path segment: %q", value)
			}
			if segment == "." || segment == ".." {
				return SpiffeID{}, fmt.Errorf("relative path segment %q is not allowed: %q", segment, value)
			}
			for _, r := range segment {
				if !isPathSegmentChar(r) {
					return SpiffeID{}, fmt.Errorf(
						"path segments may only contain letters, digits, '.', '_' and '-': %q", value)
				}
			}
		}
	}

	id := SpiffeID{TrustDomain: trustDomain}
	if hasPath {
		id.Path = "/" + path
	}
	return id, nil
}

func (id SpiffeID) String() string {
	return scheme + id.TrustDomain + id.Path
}

func isTrustDomainChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-'
}

func isPathSegmentChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
		r == '.' || r == '_' || r == '-'
}
