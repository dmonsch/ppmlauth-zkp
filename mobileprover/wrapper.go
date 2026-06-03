package mobileprover

import (
	"math/big"
	"strconv"
	"strings"
)

func GenerateProofWrapper(
	sk string,
	skHash string,
	a string,
	b int,
	claimedBit int,
) string {
	const maxElements = 1305
	// split sk into uint64 array (assuming sk is a comma-separated string)
	var skArray [maxElements]uint64
	for i, v := range strings.Split(sk, ",") {
		if i >= maxElements {
			break // limit to 32 elements
		}
		skArray[i], _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
	}
	// convert sk hash to big.Int
	skHashBigInt := new(big.Int)
	skHashBigInt.SetString(skHash, 10)

	// split a into uint64 array (assuming a is a comma-separated string)
	var aArray [maxElements]uint64
	for i, v := range strings.Split(a, ",") {
		if i >= maxElements {
			break // limit to 32 elements
		}
		aArray[i], _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
	}

	// convert b, claimedBit, mod, keyMod to big.Int
	bigB := big.NewInt(int64(b))
	claimedResultBit := big.NewInt(int64(claimedBit))

	proofResult := GenerateProof(skArray, skHashBigInt, aArray, bigB, claimedResultBit)

	return string(proofResult[:])
}
