# zkbk

`zkbk` is a collection of zero-knowledge gadgets and verifiable credential primitives built on top of the [arkworks](https://github.com/arkworks-rs) ecosystem to facilitate first-person credentials.

The repository is structured as a Cargo workspace containing two main crates:

1. **`fp-snark`**: Packages reusable SNARK-friendly primitives—Merkle trees, vector commitments, polynomial utilities, pseudorandom functions, random oracles, and Schnorr signatures—together with circuit-friendly constraint gadgets and end-to-end Groth16 integration tests.
2. **`fp-blackbox`**: Implements black-box (pairing-based) cryptographic constructions. It currently includes:
   - `gro15`: Standard and Flipped Groth15 signatures.
   - `gs08`: Groth-Sahai proofs for pairing-based statements (e.g., SXDH commitment schemes, PPE proofs).
   - `vouch`: The Vouchable Credentials construction (issuance and vouching).

## Getting Started

1. Install Rust (recommended via [`rustup`](https://rustup.rs/)) and ensure the stable toolchain is active.
2. Fetch dependencies and compile the workspace:

   ```bash
   cargo build
   ```

3. Generate docs if desired:

   ```bash
   cargo doc --open
   ```

## Repository Layout

### `fp-snark`

- `fp-snark/src/lib.rs` – Crate entry point.
- `fp-snark/src/merkle_tree/` – Layered hash configuration trait, path verification, and fixed-height Merkle tree implementation.
- `fp-snark/src/vector_commitment/bytes/` – Vector commitment interface for byte-array elements.
- `fp-snark/src/record_commitment/` – Commitment schemes (Pedersen, KZG, SHA-256) with circuit gadgets for record construction.
- `fp-snark/src/prf/` – JZ PRF abstraction backed by configurable CRHs plus constraint system gadgets.
- `fp-snark/src/random_oracle/` – Random oracle trait and a Blake2s-backed implementation for both native and R1CS contexts.
- `fp-snark/src/signature/` – Signature trait with a Schnorr implementation over JubJub.
- `fp-snark/tests/` – Heavyweight integration tests that compose the primitives into Groth16 circuits (e.g., nullifier PRFs, Pedersen commitments, and membership checks). Design diagrams supporting several tests live under `tests/designs/`.

### `fp-blackbox`

- `fp-blackbox/src/lib.rs` – Crate entry point.
- `fp-blackbox/src/gro15/` – Implementation of standard and flipped Groth15 signatures.
- `fp-blackbox/src/gs08/` – Implementation of Groth-Sahai proofs.
- `fp-blackbox/src/vouch/` – Elements of the Vouchable Credentials construction.
- `fp-blackbox/benches/` – Benchmarks for the `fp-blackbox` components.

## Running Tests

The project includes both unit tests and integration tests. On most machines, you will want to enable optimizations:

```bash
cargo test --release
```

## Contributing & License

Contributions are welcome; please open an issue or pull request with ideas or fixes. The project is licensed under the Apache License, Version 2.0. See `LICENSE` for details.
