use ark_ec::pairing::Pairing;
use ark_ec::PrimeGroup;
use ark_ff::{Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::Rng, UniformRand, Zero};

#[derive(Clone, Debug)]
pub struct Params<E: Pairing> {
    pub w1: E::G1,
    pub w2: E::G1,
    pub g: E::G1,
    pub h: E::G2,
}

impl<E: Pairing> Params<E> {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let w1_scalar = E::ScalarField::rand(rng);
        let w2_scalar = E::ScalarField::rand(rng);
        let g = E::G1::generator();
        let h = E::G2::generator();

        let w1 = g * w1_scalar;
        let w2 = g * w2_scalar;

        Params { w1, w2, g, h }
    }
}

#[derive(Clone, Debug)]
pub struct VerificationKey<E: Pairing> {
    pub v: E::G2,
}

impl<E: Pairing> VerificationKey<E> {
    pub fn verify(&self, params: &Params<E>, m1: &E::G1, m2: &E::G1, sigma: &Signature<E>) -> bool {
        // Eq 1: e(S, R) = e(W1, h) * e(g, V)
        let lhs1 = E::pairing(sigma.s, sigma.r);
        let rhs1 = E::pairing(params.w1, params.h) + E::pairing(params.g, self.v);

        if lhs1 != rhs1 {
            return false;
        }

        // Eq 2: e(T1, R) = e(M1, h) * e(W1, V)
        let lhs2 = E::pairing(sigma.t1, sigma.r);
        let rhs2 = E::pairing(m1, params.h) + E::pairing(params.w1, self.v);

        if lhs2 != rhs2 {
            return false;
        }

        // Eq 3: e(T2, R) = e(M2, h) * e(W2, V)
        let lhs3 = E::pairing(sigma.t2, sigma.r);
        let rhs3 = E::pairing(m2, params.h) + E::pairing(params.w2, self.v);

        if lhs3 != rhs3 {
            return false;
        }

        true
    }

    pub fn verify_knowledge(&self, params: &Params<E>, proof: &SchnorrProof<E>) -> bool {
        // Check h^z == A * V^c
        // Base is params.h (G2)
        // PK is self.v (G2)

        let mut bytes = Vec::new();
        proof.a.serialize_uncompressed(&mut bytes).unwrap();
        let c = hash_bytes_to_scalar::<E>(&bytes);

        let lhs = params.h * proof.z;
        let rhs = proof.a + (self.v * c);

        lhs == rhs
    }
}

#[derive(Clone, Debug)]
pub struct SecretKey<E: Pairing> {
    v: E::ScalarField,
    // Precomputed values for optimization
    v_g: E::G1,
    v_w1: E::G1,
    v_w2: E::G1,
}

impl<E: Pairing> SecretKey<E> {
    pub fn new<R: Rng>(params: &Params<E>, rng: &mut R) -> (VerificationKey<E>, Self) {
        let v = E::ScalarField::rand(rng);
        let vk_v = params.h * v;

        // Precompute values
        let v_g = params.g * v;
        let v_w1 = params.w1 * v;
        let v_w2 = params.w2 * v;

        (
            VerificationKey { v: vk_v },
            SecretKey { v, v_g, v_w1, v_w2 },
        )
    }

    /// Sign a pair of messages (M1, M2) in G1^2
    pub fn sign<R: Rng>(
        &self,
        params: &Params<E>,
        m1: &E::G1,
        m2: &E::G1,
        rng: &mut R,
    ) -> Signature<E> {
        let mut r_scalar = E::ScalarField::rand(rng);
        while r_scalar.is_zero() {
            r_scalar = E::ScalarField::rand(rng);
        }
        let r_inv = r_scalar.inverse().unwrap();

        // R := h^r
        let r_group = params.h * r_scalar;

        // S := (W1 * g^v)^(1/r)
        // optimized: g^v is self.v_g
        let s = (params.w1 + self.v_g) * r_inv;

        // T1 := (M1 * W1^v)^(1/r)
        // optimized: W1^v is self.v_w1
        let t1 = (*m1 + self.v_w1) * r_inv;

        // T2 := (M2 * W2^v)^(1/r)
        // optimized: W2^v is self.v_w2
        let t2 = (*m2 + self.v_w2) * r_inv;

        Signature {
            r: r_group,
            s,
            t1,
            t2,
        }
    }

    pub fn prove_knowledge<R: Rng>(&self, params: &Params<E>, rng: &mut R) -> SchnorrProof<E> {
        // Base is params.h
        let r = E::ScalarField::rand(rng);
        let a = params.h * r;

        let mut bytes = Vec::new();
        a.serialize_uncompressed(&mut bytes).unwrap();
        let c = hash_bytes_to_scalar::<E>(&bytes);

        let z = r + c * self.v;
        SchnorrProof { a, z }
    }
}

#[derive(Clone, Debug)]
pub struct Signature<E: Pairing> {
    pub r: E::G2,
    pub s: E::G1,
    pub t1: E::G1,
    pub t2: E::G1,
}

#[derive(Clone, Debug)]
pub struct SchnorrProof<E: Pairing> {
    pub a: E::G2,
    pub z: E::ScalarField,
}
fn hash_bytes_to_scalar<E: Pairing>(bytes: &[u8]) -> E::ScalarField {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    E::ScalarField::from_le_bytes_mod_order(out.as_bytes())
}
