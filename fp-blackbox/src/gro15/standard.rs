use ark_ec::pairing::Pairing;
use ark_ec::PrimeGroup;
use ark_ff::Field;
use ark_std::{rand::Rng, UniformRand, Zero};

#[derive(Clone, Debug)]
pub struct Params<E: Pairing> {
    pub y1: E::G2,
    pub y2: E::G2,
    pub g: E::G1,
    pub h: E::G2,
}

impl<E: Pairing> Params<E> {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        let y1_scalar = E::ScalarField::rand(rng);
        let y2_scalar = E::ScalarField::rand(rng);
        let g = E::G1::generator();
        let h = E::G2::generator();

        let y1 = h * y1_scalar;
        let y2 = h * y2_scalar;

        Params { y1, y2, g, h }
    }
}

#[derive(Clone, Debug)]
pub struct VerificationKey<E: Pairing> {
    pub v: E::G1,
}

impl<E: Pairing> VerificationKey<E> {
    pub fn verify(&self, params: &Params<E>, m1: &E::G2, m2: &E::G2, sigma: &Signature<E>) -> bool {
        // e(R, S) = e(g, Y1) * e(V, h)
        let lhs1 = E::pairing(sigma.r, sigma.s);
        let rhs1 = E::pairing(params.g, params.y1) + E::pairing(self.v, params.h);

        if lhs1 != rhs1 {
            return false;
        }

        // e(R, T1) = e(g, M1) * e(V, Y1)
        let lhs2 = E::pairing(sigma.r, sigma.t1);
        let rhs2 = E::pairing(params.g, m1) + E::pairing(self.v, params.y1);

        if lhs2 != rhs2 {
            return false;
        }

        // e(R, T2) = e(g, M2) * e(V, Y2)
        let lhs3 = E::pairing(sigma.r, sigma.t2);
        let rhs3 = E::pairing(params.g, m2) + E::pairing(self.v, params.y2);

        if lhs3 != rhs3 {
            return false;
        }

        true
    }
}

#[derive(Clone, Debug)]
pub struct SecretKey<E: Pairing> {
    /// The scalar v
    _v: E::ScalarField,
    // Precomputed values for optimization in G2
    v_h: E::G2,
    v_y1: E::G2,
    v_y2: E::G2,
}

impl<E: Pairing> SecretKey<E> {
    pub fn new<R: Rng>(params: &Params<E>, rng: &mut R) -> (VerificationKey<E>, Self) {
        let v = E::ScalarField::rand(rng);
        let vk_v = params.g * v;

        // Precompute values in G2
        // S calculation needs h^v
        let v_h = params.h * v;
        // T1 calculation needs Y1^v
        let v_y1 = params.y1 * v;
        // T2 calculation needs Y2^v
        let v_y2 = params.y2 * v;

        (
            VerificationKey { v: vk_v },
            SecretKey {
                _v: v,
                v_h,
                v_y1,
                v_y2,
            },
        )
    }

    /// Sign a pair of messages (M1, M2) in G2^2
    pub fn sign<R: Rng>(
        &self,
        params: &Params<E>,
        m1: &E::G2,
        m2: &E::G2,
        rng: &mut R,
    ) -> Signature<E> {
        // Sample r <-$ F* (non-zero)
        let mut r_scalar = E::ScalarField::rand(rng);
        while r_scalar.is_zero() {
            r_scalar = E::ScalarField::rand(rng);
        }

        let r_inv = r_scalar.inverse().unwrap();

        // R := g^r
        let r_group = params.g * r_scalar;

        // S := (Y1 * h^v)^(1/r)
        // optimized: h^v is self.v_h
        let s = (params.y1 + self.v_h) * r_inv;

        // T1 := (M1 * Y1^v)^(1/r)
        // optimized: Y1^v is self.v_y1
        let t1 = (*m1 + self.v_y1) * r_inv;

        // T2 := (M2 * Y2^v)^(1/r)
        // optimized: Y2^v is self.v_y2
        let t2 = (*m2 + self.v_y2) * r_inv;

        Signature {
            r: r_group,
            s,
            t1,
            t2,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Signature<E: Pairing> {
    pub r: E::G1,
    pub s: E::G2,
    pub t1: E::G2,
    pub t2: E::G2,
}

#[cfg(test)]
mod tests {
    use crate::gro15::standard;

    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::{test_rng, UniformRand};

    #[test]
    fn test_standard_gro15() {
        let rng = &mut test_rng();
        type E = Bls12_381;

        let params = standard::Params::<E>::new(rng);
        let (vk, sk) = standard::SecretKey::new(&params, rng);

        let m1 = <E as Pairing>::G2::rand(rng);
        let m2 = <E as Pairing>::G2::rand(rng);

        let sig = sk.sign(&params, &m1, &m2, rng);
        let valid = vk.verify(&params, &m1, &m2, &sig);

        assert!(valid, "Standard Gro15 verification failed");
    }
}
