package main

import (
	"bufio"
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"ZKProofVerDec/circuit"
	"ZKProofVerDec/witness"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	gwitness "github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

var (
	pathCCS = getenv("ZKTOOL_CCS", "./data/zk/circuit.r1cs")
	pathPK  = getenv("ZKTOOL_PK", "./data/zk/proving_key.bin")
	pathVK  = getenv("ZKTOOL_VK", "./data/zk/verifying_key.bin")
)

func loadOrCompileCCS(path string) (constraint.ConstraintSystem, error) {
	// Try reading an existing CS from disk (concrete type, not a nil interface!)
	if f, err := os.Open(path); err == nil {
		defer func(f *os.File) {
			_ = f.Close()
		}(f)
		cs := groth16.NewCS(ecc.BN254) // concrete implements ReadFrom
		if _, err := cs.ReadFrom(f); err != nil {
			return nil, fmt.Errorf("read ccs %q: %w", path, err)
		}
		return cs, nil
	}

	// Otherwise compile from the circuit type
	var c circuit.CircuitVerDec
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		return nil, fmt.Errorf("compile circuit: %w", err)
	}

	// Best-effort persist to disk (but return compile result even if save fails)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return ccs, fmt.Errorf("mkdir %q: %w", filepath.Dir(path), err)
	}
	out, err := os.Create(path)
	if err != nil {
		return ccs, fmt.Errorf("create ccs %q: %w", path, err)
	}
	if _, err := ccs.WriteTo(out); err != nil {
		_ = out.Close()
		return ccs, fmt.Errorf("write ccs %q: %w", path, err)
	}
	if err := out.Close(); err != nil {
		return ccs, fmt.Errorf("close ccs %q: %w", path, err)
	}

	return ccs, nil
}

func loadOrSetupKeys(
	ccs constraint.ConstraintSystem,
	pathPK, pathVK string,
) (groth16.ProvingKey, groth16.VerifyingKey, error) {

	// Try to open existing keys
	if fpk, err1 := os.Open(pathPK); err1 == nil {
		defer fpk.Close()
		if fvk, err2 := os.Open(pathVK); err2 == nil {
			defer fvk.Close()

			// Allocate properly (value form); these come pre-initialized for the curve.
			pk := groth16.NewProvingKey(ecc.BN254)   // value, not pointer, in your version
			vk := groth16.NewVerifyingKey(ecc.BN254) // value

			// Read into them. Calling a pointer-receiver method on an addressable value is fine.
			if _, err := pk.ReadFrom(fpk); err != nil {
				var zpk groth16.ProvingKey
				var zvk groth16.VerifyingKey
				return zpk, zvk, fmt.Errorf("read pk: %w", err)
			}
			if _, err := vk.ReadFrom(fvk); err != nil {
				var zpk groth16.ProvingKey
				var zvk groth16.VerifyingKey
				return zpk, zvk, fmt.Errorf("read vk: %w", err)
			}
			return pk, vk, nil
		}
	}

	// Otherwise: run Setup once
	pk, vk, err := groth16.Setup(ccs) // returns VALUES
	if err != nil {
		return pk, vk, err
	}

	// Persist (same behavior you had; keep it simple)
	if err := os.MkdirAll(filepath.Dir(pathPK), 0o755); err == nil {
		if out, err := os.Create(pathPK); err == nil {
			_, _ = pk.WriteTo(out)
			_ = out.Close()
		}
	}
	if err := os.MkdirAll(filepath.Dir(pathVK), 0o755); err == nil {
		if out, err := os.Create(pathVK); err == nil {
			_, _ = vk.WriteTo(out)
			_ = out.Close()
		}
	}

	return pk, vk, nil
}

type PublicInputs struct {
	SkHash           string   `json:"SkHash"`
	A                []uint64 `json:"A"`
	B                uint64   `json:"B"`
	ClaimedResultBit uint64   `json:"ClaimedResultBit"`
}

type InputVerDec struct {
	Sk               []uint64 `json:"Sk"`
	SkHash           string   `json:"SkHash"`
	A                []uint64 `json:"A"`
	B                uint64   `json:"B"`
	ClaimedResultBit uint64   `json:"ClaimedResultBit"`
}

func (in *InputVerDec) ToWitness() circuit.CircuitVerDec {
	var w circuit.CircuitVerDec
	for i := range w.Sk {
		if i < len(in.Sk) {
			w.Sk[i] = in.Sk[i]
		}
	}
	// convert sk hash from str input to uint64
	sw, _ := new(big.Int).SetString(in.SkHash, 10)
	w.SkHash = sw

	// copy A with bounds check
	for i := range w.A {
		if i < len(in.A) {
			w.A[i] = in.A[i]
		}
	}
	w.B = in.B
	w.ClaimedResultBit = in.ClaimedResultBit
	return w
}

type req struct {
	Cmd    string        `json:"cmd"`              // "prove", "prove_test", "verify"
	Input  *InputVerDec  `json:"input,omitempty"`  // for "prove"
	Proof  string        `json:"proof,omitempty"`  // base64, for "verify"
	Pub    string        `json:"pub,omitempty"`    // base64, for "verify"
	Public *PublicInputs `json:"public,omitempty"` // for "verify_with_public"
	Inputs []uint64      `json:"inputs,omitempty"` // for "poseidon_hash"
}

type resp struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Proof string `json:"proof,omitempty"`
	Pub   string `json:"pub,omitempty"`
	Hash  string `json:"hash,omitempty"` // decimal string of Poseidon hash
}

func writeJSONLine(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal error:", err)
		return err
	}
	b = append(b, '\n')
	if _, err := os.Stdout.Write(b); err != nil {
		// if Python closed the pipe: exit gracefully
		fmt.Fprintln(os.Stderr, "stdout write error:", err)
		return err
	}
	return nil
}

func unmarshalProof(pr groth16.Proof, b []byte) (err error) {
	// If one day gnark adds UnmarshalBinary, use it.
	if u, ok := any(pr).(interface{ UnmarshalBinary([]byte) error }); ok {
		return u.UnmarshalBinary(b)
	}

	// Fall back to ReaderFrom (this is implemented by gnark proofs).
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("proof ReadFrom panic: %v", r)
		}
	}()
	if _, err = pr.ReadFrom(bytes.NewReader(b)); err != nil {
		return fmt.Errorf("decode proof: %w", err)
	}
	return nil
}

func unmarshalWitness(w gwitness.Witness, b []byte) (err error) {
	if u, ok := any(w).(encoding.BinaryUnmarshaler); ok {
		return u.UnmarshalBinary(b)
	}
	type readerFrom interface {
		ReadFrom(io.Reader) (int64, error)
	}
	if rf, ok := any(w).(readerFrom); ok {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("witness ReadFrom panic: %v", r)
			}
		}()
		_, err = rf.ReadFrom(bytes.NewReader(b))
		return err
	}
	return fmt.Errorf("witness doesn't support UnmarshalBinary or ReadFrom")
}

func doProve(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, w *circuit.CircuitVerDec) (resp, error) {
	wFull, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	if err != nil {
		return resp{}, err
	}
	opts := backend.WithSolverOptions(
		solver.WithHints(circuit.ModuloHint),
		solver.WithLogger(zerolog.Nop()), // silence solver logs
	)
	proof, err := groth16.Prove(ccs, pk, wFull, opts)
	if err != nil {
		return resp{}, err
	}
	pub, err := wFull.Public()
	if err != nil {
		return resp{}, err
	}

	var pb, wb bytes.Buffer
	if _, err := proof.WriteTo(&pb); err != nil {
		return resp{}, err
	}
	if _, err := pub.WriteTo(&wb); err != nil {
		return resp{}, err
	}

	out := resp{
		Ok:    true,
		Proof: base64.StdEncoding.EncodeToString(pb.Bytes()),
		Pub:   base64.StdEncoding.EncodeToString(wb.Bytes()),
	}
	// Safety: ensure non-empty outputs
	if out.Proof == "" || out.Pub == "" {
		return resp{}, fmt.Errorf("internal: empty proof/pub after serialization")
	}
	return out, nil
}

func cmdServe() error {
	// Never let a panic kill the process; report to stderr
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "panic recovered:", r)
			fmt.Fprintln(os.Stderr, string(debug.Stack()))
		}
	}()

	ccs, err := loadOrCompileCCS(pathCCS)
	if err != nil {
		return err
	}

	pk, vk, err := loadOrSetupKeys(ccs, pathPK, pathVK) // or false to fail-fast
	if err != nil {
		return err
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil // client closed stdin
			}
			fmt.Fprintln(os.Stderr, "read error:", err)
			return err
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var q req
		if jerr := json.Unmarshal(line, &q); jerr != nil {
			_ = writeJSONLine(resp{Ok: false, Error: jerr.Error()})
			continue
		}

		switch strings.ToLower(q.Cmd) {
		case "prove":
			if q.Input == nil {
				_ = writeJSONLine(resp{Ok: false, Error: "missing input"})
				continue
			}
			w := q.Input.ToWitness()
			out, err := doProve(ccs, pk, &w)
			if err != nil {
				_ = writeJSONLine(resp{Ok: false, Error: err.Error()})
				continue
			}
			if err := writeJSONLine(out); err != nil {
				return nil
			}

		case "prove_test":
			w, err := witness.BuildWitness()
			if err != nil {
				_ = writeJSONLine(resp{Ok: false, Error: err.Error()})
				continue
			}
			out, err := doProve(ccs, pk, &w)
			if err != nil {
				_ = writeJSONLine(resp{Ok: false, Error: err.Error()})
				continue
			}
			if err := writeJSONLine(out); err != nil {
				return nil
			}

		case "verify":
			if q.Proof == "" || q.Pub == "" {
				_ = writeJSONLine(resp{Ok: false, Error: "missing proof/pub"})
				continue
			}
			pbytes, err1 := base64.StdEncoding.DecodeString(q.Proof)
			wbytes, err2 := base64.StdEncoding.DecodeString(q.Pub)
			if err1 != nil || err2 != nil {
				_ = writeJSONLine(resp{Ok: false, Error: "bad base64"})
				continue
			}
			if len(pbytes) == 0 || len(wbytes) == 0 {
				_ = writeJSONLine(resp{Ok: false, Error: "empty proof/pub"})
				continue
			}

			// Instantiate a curve-bound proof before reading (prevents panic)
			pr := groth16.NewProof(ecc.BN254)
			if _, err := pr.ReadFrom(bytes.NewReader(pbytes)); err != nil {
				_ = writeJSONLine(resp{Ok: false, Error: err.Error()})
				continue
			}

			wPub, err := gwitness.New(ecc.BN254.ScalarField())
			if err != nil {
				_ = writeJSONLine(resp{Ok: false, Error: err.Error()})
				continue
			}
			if _, err := wPub.ReadFrom(bytes.NewReader(wbytes)); err != nil {
				_ = writeJSONLine(resp{Ok: false, Error: err.Error()})
				continue
			}
			if err := groth16.Verify(pr, vk, wPub); err != nil {
				_ = writeJSONLine(resp{Ok: false, Error: err.Error()})
				continue
			}
			if err := writeJSONLine(resp{Ok: true}); err != nil {
				return nil
			}
		case "verify_with_public":
			if q.Proof == "" || q.Public == nil {
				_ = writeJSONLine(resp{Ok: false, Error: "missing proof/public"})
				continue
			}
			pbytes, err := base64.StdEncoding.DecodeString(q.Proof)
			if err != nil || len(pbytes) == 0 {
				_ = writeJSONLine(resp{Ok: false, Error: "bad or empty proof"})
				continue
			}

			pr := groth16.NewProof(ecc.BN254)
			// was: if err := unmarshalProof(&pr, pbytes); err != nil { ... }
			if err := unmarshalProof(pr, pbytes); err != nil {
				_ = writeJSONLine(resp{Ok: false, Error: "decode proof: " + err.Error()})
				continue
			}

			// Build public-only assignment
			var pubAssign circuit.CircuitVerDec
			sw, er := new(big.Int).SetString(q.Public.SkHash, 10)
			if er == false {
				_ = writeJSONLine(resp{Ok: false, Error: "bad sk hash"})
				continue
			}

			pubAssign.SkHash = sw
			for i := range pubAssign.A {
				if i < len(q.Public.A) {
					pubAssign.A[i] = q.Public.A[i]
				}
			}
			pubAssign.B = q.Public.B
			pubAssign.ClaimedResultBit = q.Public.ClaimedResultBit

			wAll, err := frontend.NewWitness(&pubAssign, ecc.BN254.ScalarField(), frontend.PublicOnly()) // TODO this is the problem
			if err != nil {
				_ = writeJSONLine(resp{Ok: false, Error: err.Error()})
				continue
			}
			wPub, err := wAll.Public()
			if err != nil {
				_ = writeJSONLine(resp{Ok: false, Error: err.Error()})
				continue
			}

			if err := groth16.Verify(pr, vk, wPub); err != nil {
				_ = writeJSONLine(resp{Ok: false, Error: err.Error()})
				continue
			}
			if err := writeJSONLine(resp{Ok: true}); err != nil {
				return nil
			}
		case "poseidon_hash":
			if len(q.Inputs) == 0 {
				_ = writeJSONLine(resp{Ok: false, Error: "missing inputs"})
				continue
			}
			skInputs := make([]*big.Int, len(q.Inputs))
			for i, v := range q.Inputs {
				skInputs[i] = new(big.Int).SetUint64(v)
			}

			// Use your existing function (chunk size 8 as requested)
			// Signature assumed: func PoseidonHashRecursive(inputs []*big.Int, chunkSize int) *big.Int
			h := witness.PoseidonHashRecursive(skInputs, 8)
			if h == nil {
				_ = writeJSONLine(resp{Ok: false, Error: "hash computation failed"})
				continue
			}

			// Return as a decimal string (easy to parse in any language)
			if err := writeJSONLine(resp{Ok: true, Hash: h.String()}); err != nil {
				return nil
			}
		default:
			_ = writeJSONLine(resp{Ok: false, Error: "unknown cmd"})
		}
	}
}

func main() {
	// Silence gnark/zerolog globally (send everything to /dev/null)
	zerolog.SetGlobalLevel(zerolog.Disabled)
	log.Logger = log.Output(io.Discard)

	if len(os.Args) >= 2 && os.Args[1] == "serve" {
		if err := cmdServe(); err != nil {
			fmt.Fprintln(os.Stderr, "serve error:", err)
			os.Exit(1)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "usage: zktool serve")
	os.Exit(2)
}
