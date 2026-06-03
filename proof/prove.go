package proof

import (
	"ZKProofVerDec/circuit"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/rs/zerolog"
)

func Prove(w circuit.CircuitVerDec) error {
	var c circuit.CircuitVerDec

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		return err
	}
	serializeCircuit(ccs)

	// Get the number of constraints
	// constraintCount := ccs.GetNbConstraints()

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return err
	}

	// serialize keys
	serializeKeys(pk, vk)

	witnessFull, _ := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	solverHints := solver.WithHints(circuit.ModuloHint)
	proverOption := backend.WithSolverOptions(solverHints, solver.WithLogger(zerolog.Nop()))
	proof, _ := groth16.Prove(ccs, pk, witnessFull, proverOption)

	publicWitness, _ := witnessFull.Public()
	return groth16.Verify(proof, vk, publicWitness)
}

func serializeCircuit(ccs constraint.ConstraintSystem) {
	// Serialize the compiled circuit
	r1csFile, err := os.Create("circuit.r1cs")
	if err != nil {
		panic(err)
	}
	_, err = ccs.WriteTo(r1csFile)
	if err != nil {
		panic(err)
	}
	r1csFile.Close()
}

func serializeKeys(pk groth16.ProvingKey, vk groth16.VerifyingKey) {
	// Serialize proving key (for mobile prover)
	pkFile, err := os.Create("proving_key.bin")
	if err != nil {
		panic(err)
	}
	_, err = pk.WriteTo(pkFile)
	if err != nil {
		panic(err)
	}
	pkFile.Close()

	// Serialize verifying key (for verifier)
	vkFile, err := os.Create("verifying_key.bin")
	if err != nil {
		panic(err)
	}
	_, err = vk.WriteTo(vkFile)
	if err != nil {
		panic(err)
	}
	vkFile.Close()
}
