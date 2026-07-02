package main

import (
	"flag"
	"fmt"
	"time"

	"ZKProofVerDec/circuit"
	"ZKProofVerDec/witness"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/rs/zerolog"
)

// Simple benchmark tool: compile circuit once, run setup once, then generate
// N proofs measuring prove and verify time per iteration.
func main() {
	n := flag.Int("n", 5, "number of proofs to generate for benchmarking")
	flag.Parse()

	fmt.Printf("Benchmarking proof generation and verification (n=%d)\n", *n)

	var c circuit.CircuitVerDec
	// compile circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		fmt.Println("compile error:", err)
		return
	}

	fmt.Println("Running trusted setup (Groth16)...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Println("setup error:", err)
		return
	}

	// prepare options
	solverHints := solver.WithHints(circuit.ModuloHint)
	proverOption := backend.WithSolverOptions(solverHints, solver.WithLogger(zerolog.Nop()))

	var proveTimes []time.Duration
	var verifyTimes []time.Duration

	for i := 0; i < *n; i++ {
		fmt.Printf("Iteration %d/%d\n", i+1, *n)
		wstruct, err := witness.BuildWitness()
		if err != nil {
			fmt.Println("build witness error:", err)
			return
		}

		witnessFull, err := frontend.NewWitness(&wstruct, ecc.BN254.ScalarField())
		if err != nil {
			fmt.Println("witness creation error:", err)
			return
		}

		// Prove
		t0 := time.Now()
		proof, err := groth16.Prove(ccs, pk, witnessFull, proverOption)
		if err != nil {
			fmt.Println("prove error:", err)
			return
		}
		dt := time.Since(t0)
		proveTimes = append(proveTimes, dt)
		fmt.Printf("  prove time: %s\n", dt)

		// Verify (use public witness)
		t1 := time.Now()
		pubW, err := witnessFull.Public()
		if err != nil {
			fmt.Println("public witness error:", err)
			return
		}
		if err := groth16.Verify(proof, vk, pubW); err != nil {
			fmt.Println("verify failed:", err)
			return
		}
		dv := time.Since(t1)
		verifyTimes = append(verifyTimes, dv)
		fmt.Printf("  verify time: %s\n", dv)
	}

	// summarize
	sum := func(ds []time.Duration) time.Duration {
		var s time.Duration
		for _, d := range ds {
			s += d
		}
		return s
	}
	avg := func(ds []time.Duration) time.Duration {
		if len(ds) == 0 {
			return 0
		}
		return sum(ds) / time.Duration(len(ds))
	}

	fmt.Println("\nResults:")
	fmt.Printf("  prove avg: %s\n", avg(proveTimes))
	fmt.Printf("  verify avg: %s\n", avg(verifyTimes))
}
