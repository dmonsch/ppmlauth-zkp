ZKProofVerDec
=================

Lightweight repository for zero-knowledge proof verification and proof generation utilities used for mobile and CLI tools.

Contents
- `cmd/zktool` - command-line tool (entrypoint)
- `circuit` - circuit definitions for gnark
- `poseidon` - Poseidon hash helper
- `proof` - proof generation
- `witness` - witness generation helpers
- `mobileprover` - mobile-friendly wrapper and caches

Getting started

Prerequisites
- Go 1.24+ (module enabled)
- git

Basic build

```sh
# fetch modules
go mod download

# build CLI tool
go build -o zktool ./cmd/zktool

# run tests
make test
```

Cleaning build artifacts

```sh
./scripts/clean.sh
```

Notes for maintainers
- The repository contains generated cryptographic artifacts and mobile frameworks in the tree for convenience during development. These are large and should not be committed to the canonical upstream; see `.gitignore` for entries that ensure generated/compiled files are ignored.
- Tests are lightweight smoke tests to make sure internal packages compile. Add more focused unit and integration tests for cryptographic code if you change core algorithms.

Poseidon attribution
- The Poseidon permutation/hash implementation used in this repository follows
  the design and recommended parameters described by Grassi et al.,
  USENIX Security 2021. See the authors' presentation: https://www.usenix.org/conference/usenixsecurity21/presentation/grassi

Secure disclosure (background)
--------------------------------
This project implements a zero-knowledge proof (ZKP) workflow used to
attest decryption correctness of an encrypted binary classifier result
while preserving confidentiality of all other runtime behavior. The
secure-disclosure procedure pursues two primary objectives:

1. Classifier decision integrity — ensure the server learns the binary
   analysis result without risk of client manipulation.
2. Confidentiality — ensure neither party learns behavioural information
   beyond the single binary analysis result.

Protocol sketch (high-level):
- The server provides the encrypted analysis result `ct_b` to the client.
- The client decrypts `ct_b` with their TFHE secret key `sk_t` to obtain
  a binary value `b_c` and produces a ZKP that the decryption is correct.
- The circuit enforces two checks:
  - `hash(sk_t) == com_sk` (secret-key commitment matches the public commitment),
  - `Dec(ct_b, sk_t) == b_c` (decryption correctness).

Variables involved (how they map to the repository):
- `sk_t`: TFHE secret key of the client (private witness input).
- `com_sk`: public commitment of the client's secret key (public input).
- `ct_b`: ciphertext encoding the binary classifier result (public input).
- `b_c`: claimed decryption result (public input).

Why the commitment matters
- Without a binding commitment to the secret key a dishonest client could
  craft a key that decrypts `ct_b` to any desired `b_c'`. By enforcing
  `hash(sk_t) == com_sk` the circuit ensures the key is fixed and bound to
  the enrollment commitment.

Cryptographic choices
- Poseidon is used for the key commitment because it is optimized for
  arithmetic circuits / ZK-friendly hashing and produces small constraint
  footprints compared to general-purpose hashes.
- Groth16 over BN254 is used for succinct, efficient proving and verification.
  Since Groth16 is circuit-specific it requires a trusted SRS setup; the
  server typically performs the setup once and derives proving/verification
  keys. For stronger security the setup can be performed as a multi-party
  computation so that at least one honest participant prevents SRS leakage.

Practical considerations
- HE (CKKS) → TFHE conversions and homomorphic operations may introduce
  small numeric errors. Carefully chosen parameters and error management
  make flipped-bits unlikely in practice, but this should be evaluated for
  each deployment.


References
- Grassi et al., Poseidon hash (USENIX Security 2021):
  https://www.usenix.org/conference/usenixsecurity21/presentation/grassi
- Jens Groth, "On the size of pairing-based non-interactive arguments",
  Proc. 35th IACR Int. Conf. on the Theory and Applications of Cryptographic
  Techniques (EUROCRYPT), Vienna, Austria, 2016, pp. 305–326. (Groth16)

Benchmarking proof generation
-----------------------------
There is a small benchmarking CLI to measure proof generation and
verification performance locally. It compiles the circuit and runs the
Groth16 setup once, then generates `n` proofs and measures timings. To
build and run it:

```sh
# build
go build -o bench ./cmd/bench

# run (default n=5)
./bench -n 3
```

Typical output contains per-iteration prove/verify times and averages. Use
it to estimate mobile client proof-generation cost or server verification
latency.


Contact
- For issues, open a GitHub issue with a reproducer and background.

Repository reinitialization
- A clean history was created locally (large binary/mobile artifacts were removed from the working tree). To publish the cleaned repository to GitHub, create a new empty repository on GitHub (do NOT initialize with README/license) and then add the remote and push:

```sh
# replace <your-remote-url> with the new GitHub repository URL
git remote add origin <your-remote-url>
git branch -M main
git push -u origin main
```



