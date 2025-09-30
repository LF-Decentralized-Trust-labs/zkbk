# zkbk

`zkbk` is a collection of zero-knowledge gadgets built on top of the [arkworks](https://github.com/arkworks-rs) ecosystem to facilitate first person credentials. The crate packages reusable primitives—Merkle trees, vector commitments, polynomial utilities, pseudorandom functions, random oracles, and Schnorr signatures—together with circuit-friendly constraint gadgets and end-to-end Groth16 integration tests.


## Getting Started
1. Install Rust (recommended via [`rustup`](https://rustup.rs/)) and ensure the stable toolchain is active.
2. Fetch dependencies and compile the library:
   ```bash
   cargo build
   ```
3. Generate docs if desired:
   ```bash
   cargo doc --open
   ```

## Repository Layout
- `src/lib.rs` – Crate entry point exporting all modules.
- `src/merkle_tree/` – Layered hash configuration trait, path verification, and fixed-height Merkle tree implementation.
- `src/vector_commitment/bytes/` – Vector commitment interface for byte-array elements.
- `src/record_commitment/` – Commitment schemes (Pedersen, KZG, SHA-256) with circuit gadgets for record construction.
- `src/prf/` – JZ PRF abstraction backed by configurable CRHs plus constraint system gadgets.
- `src/random_oracle/` – Random oracle trait and a Blake2s-backed implementation for both native and R1CS contexts.
- `src/signature/` – Signature trait with a Schnorr implementation over JubJub, including verification gadgets.
- `src/utils.rs` – Helpers for serialization, bit conversion, and polynomial/domain utilities used across modules.
- `tests/` – Heavyweight integration tests that compose the primitives into Groth16 circuits (e.g., nullifier PRFs, Pedersen commitments, and membership checks). Design diagrams supporting several tests live under `tests/designs/`.


## Running Tests
The project includes both unit tests and integration tests that synthesize and verify Groth16 proofs. On most machines you will want to enable optimizations:
```bash
cargo test --release
```

## Contributing & License
Contributions are welcome; please open an issue or pull request with ideas or fixes. The project is licensed under the Apache License, Version 2.0. See `LICENSE` for details.
