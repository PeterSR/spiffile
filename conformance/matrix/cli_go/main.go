// Parity CLI: mint or verify a token using the Go implementation.
//
// Usage:
//
//	go run . mint <root> <service> <aud-service>
//	go run . verify <root> <service> <token> <expected-sub-service>
package main

import (
	"fmt"
	"os"

	spiffile "github.com/PeterSR/spiffile/go"
)

const trustDomain = "parity.test"

func main() {
	command, root := os.Args[1], os.Args[2]
	switch command {
	case "mint":
		service, audience := os.Args[3], os.Args[4]
		identity, err := spiffile.LoadIdentity(root, service)
		must(err)
		token, err := identity.Token(fmt.Sprintf("spiffe://%s/%s", trustDomain, audience), 0)
		must(err)
		fmt.Print(token)
	case "verify":
		service, token, expected := os.Args[3], os.Args[4], os.Args[5]
		identity, err := spiffile.LoadIdentity(root, service)
		must(err)
		caller, err := identity.Verify(token, "", 0)
		must(err)
		if caller.ID.String() != fmt.Sprintf("spiffe://%s/%s", trustDomain, expected) {
			panic("unexpected caller " + caller.ID.String())
		}
		fmt.Printf("go verified caller=%s\n", caller.ID)
	default:
		panic("unknown command " + command)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
