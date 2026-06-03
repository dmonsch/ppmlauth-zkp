package circuit

import (
	"github.com/consensys/gnark/frontend"
)

type CircuitVerDec struct {
	Sk               [1305]frontend.Variable
	SkHash           frontend.Variable       `gnark:",public"`
	A                [1305]frontend.Variable `gnark:",public"`
	B                frontend.Variable       `gnark:",public"`
	ClaimedResultBit frontend.Variable       `gnark:",public"`
}

// gnark entrypoint
func (c *CircuitVerDec) Define(api frontend.API) error {
	const chunkSize = 8
	const mod = 4096 // = keyMod -> fixed in our scenario

	// 1) Hash the 128-length secret vector
	inputs := make([]frontend.Variable, 1305)
	for i := range c.Sk {
		inputs[i] = c.Sk[i]
	}
	hash := recursivePoseidonHash(api, inputs, chunkSize)
	api.AssertIsEqual(hash, c.SkHash)

	// 2. check that A is really mod 4096 (really necessary? -> I do not think so as it is public)
	// (but just keep for now) => at least for sk it is necessary!
	for i := range c.Sk {
		// enforce 0 <= Sk[i] < 2^12 by constraining it to 12 boolean bits
		bits := api.ToBinary(c.Sk[i], 12) // 12 booleans
		api.AssertIsEqual(c.Sk[i], api.FromBinary(bits...))
	}

	// compute the claimed result bit
	inner := frontend.Variable(0)
	for i := range c.A {
		inner = api.Add(inner, api.Mul(c.Sk[i], c.A[i]))
	}
	inner = ModuloWithConstraints(api, inner, mod)

	// r = (B - inner + Mod) % Mod
	r := api.Sub(api.Add(c.B, mod), inner)
	r = ModuloWithConstraints(api, r, mod)

	// r = (r + Mod / (2 * 2)) % Mod  (p assumed 2)
	p, _ := api.ConstantValue(2)
	p2 := api.Mul(p, 2) // 4
	r = api.Add(r, api.Div(mod, p2))
	r = ModuloWithConstraints(api, r, mod)

	// resultBit = 1 - floor((p * r) / Mod
	multP := api.Mul(p, r)
	remFinal := ModuloWithConstraints(api, multP, mod)
	floored := api.Sub(multP, remFinal)
	resultBit := api.Div(floored, mod)
	resultBit = api.Sub(1, resultBit) // flip bit

	// Constrain the claimed bit
	api.AssertIsEqual(resultBit, c.ClaimedResultBit)

	return nil
}
