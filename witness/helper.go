package witness

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

func PoseidonHashRecursive(inputs []*big.Int, chunkSize int) *big.Int {
	if chunkSize > 16 || chunkSize < 1 {
		panic("chunkSize must be between 1 and 16")
	}

	n := len(inputs)

	// Base case: if the number of inputs fits in one hash, just hash it
	if n <= chunkSize {
		// Pad with zeros if needed
		if n < chunkSize {
			pad := make([]*big.Int, chunkSize-n)
			for i := range pad {
				pad[i] = big.NewInt(0)
			}
			inputs = append(inputs, pad...)
		}
		hash, err := poseidon.Hash(inputs)
		if err != nil {
			panic(err)
		}
		return hash
	}

	// Step 1: hash each chunk
	var intermediateHashes []*big.Int
	for i := 0; i < n; i += chunkSize {
		end := i + chunkSize
		if end > n {
			end = n
		}
		chunk := inputs[i:end]

		// pad with zeros if needed
		if len(chunk) < chunkSize {
			pad := make([]*big.Int, chunkSize-len(chunk))
			for i := range pad {
				pad[i] = big.NewInt(0)
			}
			chunk = append(chunk, pad...)
		}
		hash, err := poseidon.Hash(chunk)
		if err != nil {
			panic(err)
		}
		intermediateHashes = append(intermediateHashes, hash)
	}

	// Step 2: recurse on intermediate hashes
	return PoseidonHashRecursive(intermediateHashes, chunkSize)
}
