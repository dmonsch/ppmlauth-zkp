// Package mobileprover provides a thin wrapper to generate Groth16 proofs
// in environments where loading keys and circuit descriptions repeatedly is
// expensive (e.g. mobile). It exposes a simple cache initialization and a
// GenerateProof function intended to be called from platform bindings.
package mobileprover

import (
	"ZKProofVerDec/circuit"
	"bytes"
	"math/big"
	"os"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std"
)

// Global variables to cache circuit and proving key
var (
	r1csCache   constraint.ConstraintSystem
	pkCache     groth16.ProvingKey
	cacheLock   sync.Mutex
	initialized bool
)

// InitializeCache loads circuit and proving key into memory
func InitializeCache(circuitPath, provingKeyPath string) string {
	cacheLock.Lock()
	defer cacheLock.Unlock()

	if initialized {
		return "Already initialized"
	}

	// Load circuit
	r1csFile, err := os.Open(circuitPath)
	if err != nil {
		return err.Error()
	}
	defer r1csFile.Close()
	r1csCache = groth16.NewCS(ecc.BN254)
	_, err = r1csCache.ReadFrom(r1csFile)
	if err != nil {
		return err.Error()
	}

	// Load proving key
	pkFile, err := os.Open(provingKeyPath)
	if err != nil {
		return err.Error()
	}
	defer pkFile.Close()
	pkCache = groth16.NewProvingKey(ecc.BN254)
	_, err = pkCache.ReadFrom(pkFile)
	if err != nil {
		return err.Error()
	}

	initialized = true
	return "Cache initialized successfully"
}

// GenerateProof generates a proof using cached circuit and proving key
func GenerateProof(sk [1305]uint64, skHash *big.Int, a [1305]uint64, b *big.Int, claimedResultBit *big.Int) []byte {
	cacheLock.Lock()
	defer cacheLock.Unlock()

	if !initialized {
		return []byte("Cache not initialized")
	}

	// Create witness
	var assignment circuit.CircuitVerDec
	for i := range sk {
		assignment.Sk[i] = frontend.Variable(sk[i])
		assignment.A[i] = frontend.Variable(a[i])
	}
	assignment.SkHash = frontend.Variable(skHash)
	assignment.B = frontend.Variable(b)
	assignment.ClaimedResultBit = frontend.Variable(claimedResultBit)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return []byte(err.Error())
	}

	// Generate proof using cached objects
	std.RegisterHints()
	solverHints := solver.WithHints(circuit.ModuloHint)
	proverOption := backend.WithSolverOptions(solverHints)
	proof, err := groth16.Prove(r1csCache, pkCache, witness, proverOption)
	if err != nil {
		return []byte(err.Error())
	}

	// Serialize proof
	var proofBuf bytes.Buffer
	_, err = proof.WriteTo(&proofBuf)
	if err != nil {
		return []byte(err.Error())
	}
	return proofBuf.Bytes()
}
