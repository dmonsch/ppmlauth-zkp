package circuit

import (
	"ZKProofVerDec/poseidon"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

// moduloHint computes quotient and remainder for v % newModulus
func ModuloHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	v, modulus := inputs[0], inputs[1]
	quotient := new(big.Int).Div(v, modulus)
	remainder := new(big.Int).Sub(v, new(big.Int).Mul(quotient, modulus))
	if remainder.Sign() < 0 {
		remainder.Add(remainder, modulus)
		quotient.Sub(quotient, big.NewInt(1))
	}
	outputs[0] = quotient
	outputs[1] = remainder
	return nil
}

func ModuloWithConstraints(api frontend.API, v, modulus frontend.Variable) frontend.Variable {
	constZero, _ := api.ConstantValue(0)
	constOne, _ := api.ConstantValue(1)

	outputs, err := api.Compiler().NewHint(ModuloHint, 2, v, modulus)
	if err != nil {
		return nil
	}
	quotient, remainder := outputs[0], outputs[1]

	// Constraint: result = quotient * newModulus + remainder (IMPORTANT!)
	api.AssertIsEqual(v, api.Add(api.Mul(quotient, modulus), remainder))

	// Constraint: 0 <= remainder < newModulus
	api.AssertIsLessOrEqual(constZero, remainder)
	api.AssertIsLessOrEqual(remainder, api.Sub(modulus, constOne))

	return remainder
}

func recursivePoseidonHash(api frontend.API, inputs []frontend.Variable, chunkSize int) frontend.Variable {
	if len(inputs) <= chunkSize {
		// Pad to chunkSize with 0s if needed
		padded := make([]frontend.Variable, chunkSize)
		copy(padded, inputs)
		for i := len(inputs); i < chunkSize; i++ {
			padded[i], _ = api.ConstantValue(0)
		}
		return poseidon.Poseidon(api, padded)
	}

	// Split inputs into chunks of chunkSize, hash each
	var intermediateHashes []frontend.Variable
	for i := 0; i < len(inputs); i += chunkSize {
		end := i + chunkSize
		if end > len(inputs) {
			end = len(inputs)
		}
		chunk := inputs[i:end]

		// Pad if needed
		padded := make([]frontend.Variable, chunkSize)
		copy(padded, chunk)
		for j := len(chunk); j < chunkSize; j++ {
			padded[j], _ = api.ConstantValue(0)
		}

		chunkHash := poseidon.Poseidon(api, padded)
		intermediateHashes = append(intermediateHashes, chunkHash)
	}

	// Recursively hash intermediate hashes
	return recursivePoseidonHash(api, intermediateHashes, chunkSize)
}

func switchModulo(api frontend.API, s [32]frontend.Variable, oldModulus, newModulus frontend.Variable) [32]frontend.Variable {
	// Initialize output array
	var switched [32]frontend.Variable

	// Constants
	constZero, _ := api.ConstantValue(0)
	constOne, _ := api.ConstantValue(1)
	constTwo, _ := api.ConstantValue(2)

	// Compute halfQ = oldModulus / 2
	halfQ := api.Div(oldModulus, constTwo)

	// Compute diff = |oldModulus - newModulus|
	cmpMod := cmp.IsLess(api, newModulus, oldModulus)
	diff := api.Select(
		cmpMod,                          // newModulus < oldModulus
		api.Sub(oldModulus, newModulus), // diff = oldModulus - newModulus
		api.Sub(newModulus, oldModulus), // diff = newModulus - oldModulus
	)

	// Determine if newModulus > oldModulus
	isIncreased := api.IsZero(api.Sub(cmpMod, constOne))

	for i := range s {
		// Check if s[i] > halfQ
		// cmpHalfQ := api.Cmp(s[i], halfQ)
		cmpHalfQ := cmp.IsLessOrEqual(api, halfQ, s[i])
		isLarge := api.IsZero(api.Sub(cmpHalfQ, constOne))

		// Case: newModulus > oldModulus
		plusTerm := api.Add(s[i], api.Mul(isLarge, diff))

		// Case: newModulus < oldModulus
		isLargeDiff := cmp.IsLessOrEqual(api, diff, s[i])
		minusTerm1 := api.Sub(s[i], api.Mul(isLarge, diff))
		minusTerm2 := api.Sub(newModulus, api.Sub(diff, s[i]))
		minusTerm := api.Select(isLarge, api.Select(isLargeDiff, minusTerm1, minusTerm2), s[i])

		// Select plusTerm or minusTerm based on isIncreased
		result := api.Select(isIncreased, plusTerm, minusTerm)

		// Apply modulo newModulus using hint
		outputs, err := api.Compiler().NewHint(ModuloHint, 2, result, newModulus)
		if err != nil {
			return switched
		}
		quotient, remainder := outputs[0], outputs[1]

		// Constraint: result = quotient * newModulus + remainder (IMPORTANT!)
		api.AssertIsEqual(result, api.Add(api.Mul(quotient, newModulus), remainder))

		// Constraint: 0 <= remainder < newModulus
		api.AssertIsLessOrEqual(constZero, remainder)
		api.AssertIsLessOrEqual(remainder, api.Sub(newModulus, constOne))

		switched[i] = remainder
	}

	return switched
}

func switchModulo128(api frontend.API, s [1302]frontend.Variable, oldModulus, newModulus frontend.Variable) [1302]frontend.Variable {
	var out [1302]frontend.Variable

	constZero, _ := api.ConstantValue(0)
	constOne, _ := api.ConstantValue(1)
	constTwo, _ := api.ConstantValue(2)

	halfQ := api.Div(oldModulus, constTwo)

	// cmpMod = (newModulus < oldModulus) in {0,1}
	cmpMod := cmp.IsLess(api, newModulus, oldModulus)

	// diff = |oldModulus - newModulus|
	diff := api.Select(
		cmpMod,
		api.Sub(oldModulus, newModulus),
		api.Sub(newModulus, oldModulus),
	)

	// isIncreased = (newModulus > oldModulus) in {0,1}
	isIncreased := api.IsZero(api.Sub(cmpMod, constOne))

	halfQBits := api.ToBinary(halfQ, 64)
	diffBits := api.ToBinary(diff, 64)
	constZeroBits := api.ToBinary(constZero, 64)
	newModulusDiffBits := api.ToBinary(api.Sub(newModulus, constOne), 64)

	for i := range s {
		// isLarge = (s[i] >= halfQ) in {0,1}
		cmpHalfQ := cmp.IsLessOrEqualBinary(api, halfQBits, api.ToBinary(s[i], 64)) // just 64 bit comparison to ease comparison
		isLarge := cmp.IsEqual(api, cmpHalfQ, constOne)

		// Case new > old: add diff if large
		plusTerm := api.Add(s[i], api.Mul(isLarge, diff))

		// Case new < old: subtract diff if large; otherwise wrap
		isLargeDiff := cmp.IsLessOrEqualBinary(api, diffBits, api.ToBinary(s[i], 64)) // just 64 bit comparison to ease comparison
		minusTerm1 := api.Sub(s[i], api.Mul(isLarge, diff))
		minusTerm2 := api.Sub(newModulus, api.Sub(diff, s[i]))
		minusTerm := api.Select(isLarge, api.Select(isLargeDiff, minusTerm1, minusTerm2), s[i])

		result := api.Select(isIncreased, plusTerm, minusTerm)

		// Reduce modulo newModulus via hint
		outs, err := api.Compiler().NewHint(ModuloHint, 2, result, newModulus)
		if err != nil {
			return out
		}
		q, r := outs[0], outs[1]

		rBits := api.ToBinary(r, 64)
		api.AssertIsEqual(result, api.Add(api.Mul(q, newModulus), r))
		less1 := cmp.IsLessOrEqualBinary(api, constZeroBits, rBits)      // just 64 bit comparison to ease comparison
		less2 := cmp.IsLessOrEqualBinary(api, rBits, newModulusDiffBits) // just 64 bit comparison to ease comparison
		// lower/upper bound checks enforced via binary comparisons above

		api.AssertIsEqual(constOne, less1)
		api.AssertIsEqual(constOne, less2)

		out[i] = r
	}

	return out
}
