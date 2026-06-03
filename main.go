// Small example entrypoint used during development. The full CLI lives in
// cmd/zktool. This program builds the default witness and runs the prover.
package main

import (
	"ZKProofVerDec/proof"
	"ZKProofVerDec/witness"
)

func main() {
	w, err := witness.BuildWitness()
	if err != nil {
		panic(err)
	}

	err = proof.Prove(w)
	if err != nil {
		panic("❌ Proof failed: " + err.Error())
	}

}
