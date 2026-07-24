ZKProofVerDec
=================

ZKProofVerDec is a compact Go codebase for secure-disclosure proofs in the
TFHE/FHEW setting. It focuses on proving that a decryption was performed
correctly while keeping the surrounding private information hidden.

The repository is organized around a circuit implementation, witness
construction helpers, proof-generation utilities, and small command-line
tools for local experimentation and benchmarking.

Repository structure
- `circuit` contains the gnark circuit definition and constraint helpers.
- `witness` prepares the private and public witness values used by the circuit.
- `proof` compiles the circuit, runs setup, generates proofs, and verifies them.
- `poseidon` provides the hashing primitives used for commitment-style checks.
- `mobileprover` offers a lightweight interface for mobile-oriented proof use.
- `cmd/zktool` is the primary CLI entrypoint.
- `cmd/bench` benchmarks proof generation and verification performance.

Typical workflow
- build the circuit and supporting binaries,
- generate a witness from the configured inputs,
- produce a Groth16 proof,
- verify the proof against the public inputs,
- optionally benchmark repeated proof and verification runs.

The repository is intentionally kept concise and implementation-focused: it
documents the code layout, the major building blocks, and the available local
tooling without going into protocol-level details.

Build

```sh
go mod download
go build ./...
```

Tests

```sh
go test ./...
```

Optional benchmarks

```sh
go run ./cmd/bench -n 3
```

The benchmark writes raw latency samples to `bench_raw_latencies.csv` by
default. Use `-raw-out path/to/file.csv` to choose another file, or
`-raw-out ""` to disable file output.

Cleaning

```sh
./scripts/clean.sh
```

