package spiffile

import (
	"encoding/json"
	"testing"
)

// Fixture generated with the spiffile Python reference implementation —
// both implementations must derive the identical JWK (incl. RFC 7638
// thumbprint kid) from the same private key.
const pythonGeneratedPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbm9u3/uAu8gdCJ69
v/Tz1yQeRWbMf6rRqYUVI/nkcv6hRANCAAQmgXNhD2t1LluMV9H5K0jYe+9074On
IY8AaE1wZa/l7Abi0erjZSX0lFurDKlBUVbXSmOsV03FExfnE334Ymu8
-----END PRIVATE KEY-----`

const pythonGeneratedJWK = `{"kty": "EC", "crv": "P-256", "x": "JoFzYQ9rdS5bjFfR-StI2HvvdO-DpyGPAGhNcGWv5ew", "y": "BuLR6uNlJfSUW6sMqUFRVtdKY6xXTcUTF-cTffhia7w", "kid": "dmDENmL5k_tmVsqSCLqzdzAqm9gEkVGlHHDdAgc0qgs", "use": "jwt-svid", "alg": "ES256"}`

func TestPublicJWKMatchesPythonImplementation(t *testing.T) {
	got, err := PublicJWKFromPEM([]byte(pythonGeneratedPEM))
	if err != nil {
		t.Fatalf("PublicJWKFromPEM: %v", err)
	}
	var want JWK
	if err := json.Unmarshal([]byte(pythonGeneratedJWK), &want); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if got != want {
		t.Errorf("JWK mismatch:\n got:  %+v\n want: %+v", got, want)
	}
}

func TestGenerateRoundtrip(t *testing.T) {
	pemBytes, err := GeneratePrivateKeyPEM()
	if err != nil {
		t.Fatalf("GeneratePrivateKeyPEM: %v", err)
	}
	jwk, err := PublicJWKFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("PublicJWKFromPEM: %v", err)
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.Kid == "" || jwk.Alg != Algorithm || jwk.Use != JWTSVIDUse {
		t.Errorf("unexpected JWK: %+v", jwk)
	}
}

func TestMarshalBundle(t *testing.T) {
	doc, err := MarshalBundle(Bundle{
		TrustDomain:     "example.org",
		SpiffileVersion: BundleVersion,
		Identities: map[string]KeySet{
			"spiffe://example.org/orders": {Keys: []json.RawMessage{json.RawMessage(pythonGeneratedJWK)}},
		},
	})
	if err != nil {
		t.Fatalf("MarshalBundle: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("bundle is not valid JSON: %v", err)
	}
	if parsed["trust_domain"] != "example.org" || parsed["spiffile_version"] != float64(1) {
		t.Errorf("unexpected bundle: %s", doc)
	}
}
