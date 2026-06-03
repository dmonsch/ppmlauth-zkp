package tests

import (
	"testing"

	// blank imports ensure packages compile in CI / during `go test ./...`
	_ "ZKProofVerDec/circuit"
	_ "ZKProofVerDec/mobileprover"
	_ "ZKProofVerDec/poseidon"
	_ "ZKProofVerDec/proof"
	_ "ZKProofVerDec/witness"
)

func TestPackagesCompile(t *testing.T) {
	// If the packages do not compile the blank imports above will fail at build time
}
