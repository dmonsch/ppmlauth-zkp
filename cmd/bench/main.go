package main

import (
	"flag"
	"fmt"
	"math"
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

	// Compile circuit
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

	// Prepare options
	solverHints := solver.WithHints(circuit.ModuloHint)
	proverOption := backend.WithSolverOptions(
		solverHints,
		solver.WithLogger(zerolog.Nop()),
	)

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
		proveTime := time.Since(t0)
		proveTimes = append(proveTimes, proveTime)
		fmt.Printf("  prove time: %s\n", proveTime)

		// Verify using public witness
		pubW, err := witnessFull.Public()
		if err != nil {
			fmt.Println("public witness error:", err)
			return
		}

		t1 := time.Now()
		if err := groth16.Verify(proof, vk, pubW); err != nil {
			fmt.Println("verify failed:", err)
			return
		}
		verifyTime := time.Since(t1)
		verifyTimes = append(verifyTimes, verifyTime)
		fmt.Printf("  verify time: %s\n", verifyTime)
	}

	printStats := func(label string, ds []time.Duration) {
		mean, lower, upper, halfWidth, ok := meanConfidenceInterval95(ds)

		fmt.Printf("  %s avg: %s\n", label, mean)

		if !ok {
			fmt.Printf("  %s 95%% CI: unavailable, need at least 2 samples\n", label)
			return
		}

		fmt.Printf(
			"  %s 95%% CI: [%s, %s] ± %s\n",
			label,
			lower,
			upper,
			halfWidth,
		)
	}

	fmt.Println("\nResults:")
	printStats("prove", proveTimes)
	printStats("verify", verifyTimes)
}

// meanConfidenceInterval95 returns the sample mean and a two-sided 95%
// confidence interval using Student's t critical values.
//
// The CI is computed as:
//
//	mean ± t_(0.975, n-1) * sampleStdDev / sqrt(n)
//
// It returns ok=false when fewer than 2 samples are provided.
func meanConfidenceInterval95(ds []time.Duration) (
	mean time.Duration,
	lower time.Duration,
	upper time.Duration,
	halfWidth time.Duration,
	ok bool,
) {
	n := len(ds)
	if n == 0 {
		return 0, 0, 0, 0, false
	}

	values := make([]float64, n)

	var sum float64
	for i, d := range ds {
		values[i] = float64(d.Nanoseconds())
		sum += values[i]
	}

	meanNs := sum / float64(n)
	mean = time.Duration(meanNs)

	if n < 2 {
		return mean, 0, 0, 0, false
	}

	var squaredDiffs float64
	for _, v := range values {
		diff := v - meanNs
		squaredDiffs += diff * diff
	}

	sampleVariance := squaredDiffs / float64(n-1)
	sampleStdDev := math.Sqrt(sampleVariance)

	tCritical := tCritical95TwoSided(n - 1)
	marginNs := tCritical * sampleStdDev / math.Sqrt(float64(n))

	lowerNs := meanNs - marginNs
	upperNs := meanNs + marginNs

	if lowerNs < 0 {
		lowerNs = 0
	}

	return time.Duration(meanNs),
		time.Duration(lowerNs),
		time.Duration(upperNs),
		time.Duration(marginNs),
		true
}

// tCritical95TwoSided returns an approximate two-sided 95% Student's t critical
// value for the given degrees of freedom.
//
// Exact table values are used up to df=30. For larger df, the values approach
// the standard normal critical value of 1.96.
func tCritical95TwoSided(df int) float64 {
	table := map[int]float64{
		1:  12.706,
		2:  4.303,
		3:  3.182,
		4:  2.776,
		5:  2.571,
		6:  2.447,
		7:  2.365,
		8:  2.306,
		9:  2.262,
		10: 2.228,
		11: 2.201,
		12: 2.179,
		13: 2.160,
		14: 2.145,
		15: 2.131,
		16: 2.120,
		17: 2.110,
		18: 2.101,
		19: 2.093,
		20: 2.086,
		21: 2.080,
		22: 2.074,
		23: 2.069,
		24: 2.064,
		25: 2.060,
		26: 2.056,
		27: 2.052,
		28: 2.048,
		29: 2.045,
		30: 2.042,
	}

	if v, ok := table[df]; ok {
		return v
	}

	if df <= 40 {
		return 2.021
	}
	if df <= 60 {
		return 2.000
	}
	if df <= 120 {
		return 1.980
	}

	return 1.960
}
