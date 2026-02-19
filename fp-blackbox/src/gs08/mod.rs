use ark_ec::pairing::Pairing;
use ark_std::{rand, UniformRand, Zero};

/// Contains implementations for the SXDH based commitment schemes used in Groth-Sahai proofs.
#[derive(Debug, Clone)]
pub struct ProverKey<E: Pairing> {
    pub p1: E::G1,
    pub p2: E::G2,
    pub hg1: E::G1,

    pub u1: [E::G1; 2],
    pub u2: [E::G1; 2],
    pub v1: [E::G2; 2],
    pub v2: [E::G2; 2],

    pub u: [E::G1; 2],
    pub v: [E::G2; 2],

    pub i1: [E::G1; 2],
    pub i2: [E::G2; 2],
}

impl<E: Pairing> ProverKey<E> {
    /// Generates a new commitment key.
    pub fn setup<R: rand::RngCore>(rng: &mut R) -> Self {
        let p1 = E::G1::rand(rng);
        let p2 = E::G2::rand(rng);
        let hg1 = E::G1::rand(rng); //should be output of random oracle -- hashtocurve

        let alpha1 = E::ScalarField::rand(rng);
        let u1 = [p1.clone(), p1 * alpha1];

        let t1 = E::ScalarField::rand(rng);
        let u2 = [u1[0] * t1, u1[1] * t1];

        let alpha2 = E::ScalarField::rand(rng);
        let v1 = [p2.clone(), p2 * alpha2];

        let t2 = E::ScalarField::rand(rng);
        let v2 = [v1[0] * t2, v1[1] * t2];

        let u = [u2[0], u2[1] + p1];
        let v = [v2[0], v2[1] + p2];

        let i1 = [-u[0], -u[1]];
        let i2 = [-v[0], -v[1]];

        ProverKey {
            p1,
            p2,
            hg1,
            u1,
            u2,
            v1,
            v2,
            u,
            v,
            i1,
            i2,
        }
    }

    /// Commit to an Fr element and output a commitment in G1
    pub fn commit_fr1<R: rand::RngCore>(
        &self,
        m: &E::ScalarField,
        rng: &mut R,
    ) -> ([E::G1; 2], E::ScalarField) {
        let r = E::ScalarField::rand(rng);
        (
            [
                (self.u1[0] * r) + (self.u2[0] * m),
                (self.u1[1] * r) + (self.u2[1] * m) + (self.u1[0] * m),
            ],
            r,
        )
    }

    /// Commit to an Fr element and output a commitment in G2
    pub fn commit_fr2<R: rand::RngCore>(
        &self,
        m: &E::ScalarField,
        rng: &mut R,
    ) -> ([E::G2; 2], E::ScalarField) {
        let r = E::ScalarField::rand(rng);
        (
            [
                (self.v1[0] * r) + (self.v2[0] * m),
                (self.v1[1] * r) + (self.v2[1] * m) + (self.v1[0] * m),
            ],
            r,
        )
    }

    /// Commit to a G1 element
    pub fn commit_g1<R: rand::RngCore>(
        &self,
        m: &E::G1,
        rng: &mut R,
    ) -> ([E::G1; 2], [E::ScalarField; 2]) {
        let r = [E::ScalarField::rand(rng), E::ScalarField::rand(rng)];
        (
            [
                (self.u1[0] * r[0]) + (self.u2[0] * r[1]),
                (self.u1[1] * r[0]) + (self.u2[1] * r[1]) + m,
            ],
            r,
        )
    }

    /// Commit to a G2 element
    pub fn commit_g2<R: rand::RngCore>(
        &self,
        m: &E::G2,
        rng: &mut R,
    ) -> ([E::G2; 2], [E::ScalarField; 2]) {
        let r = [E::ScalarField::rand(rng), E::ScalarField::rand(rng)];
        (
            [
                self.v1[0] * r[0] + self.v2[0] * r[1],
                self.v1[1] * r[0] + self.v2[1] * r[1] + m,
            ],
            r,
        )
    }

    /// Prove that e(A, B) + sum(e(F_i, D_i)) + sum(e(C_j, H_j)) = T
    /// A, B are witnesses (quadratic term)
    /// F_i are constants, D_i are witnesses (linear terms type 1)
    /// C_j are witnesses, H_j are constants (linear terms type 2)
    #[allow(clippy::too_many_arguments)]
    pub fn prove_ppe<R: rand::RngCore>(
        &self,
        rng: &mut R,
        // Quadratic term A (G1 Witness) * B (G2 Witness)
        quad: Option<(&E::G1, &[E::ScalarField; 2], &E::G2, &[E::ScalarField; 2])>,
        // Linear terms F (G1 CONST) * D (G2 Witness)
        lin1: &[(&E::G1, &[E::ScalarField; 2])],
        // Linear terms C (G1 Witness) * H (G2 CONST)
        lin2: &[(&[E::ScalarField; 2], &E::G2)],
    ) -> ([[E::G1; 2]; 2], [[E::G2; 2]; 2]) {
        // 1. Randomness for the proof (tt)
        let mut tt = [[E::ScalarField::zero(); 2]; 2];
        for i in 0..2 {
            for j in 0..2 {
                tt[i][j] = E::ScalarField::rand(rng);
            }
        }

        // 2. Compute rs matrix from quadratic term randomness
        let mut rs = [[E::ScalarField::zero(); 2]; 2];
        if let Some((_, r_a, _, r_b)) = quad {
            for i in 0..2 {
                for j in 0..2 {
                    rs[i][j] = r_a[i] * r_b[j];
                }
            }
        }

        // 3. Compute Theta (G1 part of proof)
        let mut theta = [[E::G1::zero(); 2]; 2];
        theta[0][0] = self.u1[0] * tt[0][0] + self.u2[0] * tt[1][0];
        theta[1][0] = self.u1[0] * tt[0][1] + self.u2[0] * tt[1][1];
        theta[0][1] = self.u1[1] * tt[0][0] + self.u2[1] * tt[1][0];
        theta[1][1] = self.u1[1] * tt[0][1] + self.u2[1] * tt[1][1];

        // Add Quadratic Contribution: A * r_B
        if let Some((a, _, _, r_b)) = quad {
            theta[0][1] += *a * r_b[0];
            theta[1][1] += *a * r_b[1];
        }

        // Add Linear Type 1 Contribution: F * r_D (F is const G1, D is wit G2)
        for (f, r_d) in lin1 {
            theta[0][1] += **f * r_d[0];
            theta[1][1] += **f * r_d[1];
        }

        // 4. Compute Pi (G2 part of proof)
        let mut pi = [[E::G2::zero(); 2]; 2];

        // Base Pi
        pi[0][0] = self.v1[0] * (rs[0][0] - tt[0][0]) + self.v2[0] * (rs[0][1] - tt[0][1]);
        pi[1][0] = self.v1[0] * (rs[1][0] - tt[1][0]) + self.v2[0] * (rs[1][1] - tt[1][1]);
        pi[0][1] = self.v1[1] * (rs[0][0] - tt[0][0]) + self.v2[1] * (rs[0][1] - tt[0][1]);
        pi[1][1] = self.v1[1] * (rs[1][0] - tt[1][0]) + self.v2[1] * (rs[1][1] - tt[1][1]);

        // Add Quadratic Contribution: B * r_A
        if let Some((_, r_a, b, _)) = quad {
            pi[0][1] += *b * r_a[0];
            pi[1][1] += *b * r_a[1];
        }

        // Add Linear Type 2 Contribution: H * r_C (H is const G2, C is wit G1)
        for (r_c, h) in lin2 {
            pi[0][1] += **h * r_c[0];
            pi[1][1] += **h * r_c[1];
        }

        (theta, pi)
    }

    /// Verify a PPE proof
    #[allow(clippy::too_many_arguments)]
    pub fn verify_ppe(
        &self,
        // Quadratic: Com(A), Com(B)
        quad: Option<(&[E::G1; 2], &[E::G2; 2])>,
        // Lin1: F, Com(D)
        lin1: &[(&E::G1, &[E::G2; 2])],
        // Lin2: Com(C), H
        lin2: &[(&[E::G1; 2], &E::G2)],
        target: ark_ec::pairing::PairingOutput<E>,
        theta: &[[E::G1; 2]; 2],
        pi: &[[E::G2; 2]; 2],
    ) -> bool {
        use ark_ff::Zero;

        // Check 1: (0,0)
        // LHS = e(ComA[0], ComB[0])
        let mut lhs1 = ark_ec::pairing::PairingOutput::<E>::zero();
        if let Some((com_a, com_b)) = quad {
            lhs1 += E::pairing(com_a[0], com_b[0]);
        }

        let rhs1 = E::pairing(theta[0][0], self.v1[0])
            + E::pairing(theta[1][0], self.v2[0])
            + E::pairing(self.u1[0], pi[0][0])
            + E::pairing(self.u2[0], pi[1][0]);

        if lhs1 != rhs1 {
            return false;
        }

        // Check 2: (0,1)
        // LHS = e(ComA[0], ComB[1]) + sum(e(ComC[0], H))
        let mut lhs2 = ark_ec::pairing::PairingOutput::<E>::zero();
        if let Some((com_a, com_b)) = quad {
            lhs2 += E::pairing(com_a[0], com_b[1]);
        }
        for (com_c, h) in lin2 {
            lhs2 += E::pairing(com_c[0], *h);
        }

        let rhs2 = E::pairing(theta[0][0], self.v1[1])
            + E::pairing(theta[1][0], self.v2[1])
            + E::pairing(self.u1[0], pi[0][1])
            + E::pairing(self.u2[0], pi[1][1]);

        if lhs2 != rhs2 {
            return false;
        }

        // Check 3: (1,0)
        // LHS = e(ComA[1], ComB[0]) + sum(e(F, ComD[0]))
        let mut lhs3 = ark_ec::pairing::PairingOutput::<E>::zero();
        if let Some((com_a, com_b)) = quad {
            lhs3 += E::pairing(com_a[1], com_b[0]);
        }
        for (f, com_d) in lin1 {
            lhs3 += E::pairing(*f, com_d[0]);
        }

        let rhs3 = E::pairing(theta[0][1], self.v1[0])
            + E::pairing(theta[1][1], self.v2[0])
            + E::pairing(self.u1[1], pi[0][0])
            + E::pairing(self.u2[1], pi[1][0]);

        if lhs3 != rhs3 {
            return false;
        }

        // Check 4: (1,1)
        // LHS = e(ComA[1], ComB[1]) + sum(e(F, ComD[1])) + sum(e(ComC[1], H))
        let mut lhs4 = ark_ec::pairing::PairingOutput::<E>::zero();
        if let Some((com_a, com_b)) = quad {
            lhs4 += E::pairing(com_a[1], com_b[1]);
        }
        for (f, com_d) in lin1 {
            lhs4 += E::pairing(*f, com_d[1]);
        }
        for (com_c, h) in lin2 {
            lhs4 += E::pairing(com_c[1], *h);
        }

        let rhs4 = target
            + E::pairing(theta[0][1], self.v1[1])
            + E::pairing(theta[1][1], self.v2[1])
            + E::pairing(self.u1[1], pi[0][1])
            + E::pairing(self.u2[1], pi[1][1]);

        lhs4 == rhs4
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::{bls12::Bls12, PrimeGroup};
    use ark_std::{test_rng, Zero};

    type Fr = <Bls12<ark_bls12_381::Config> as Pairing>::ScalarField;
    type G1 = <Bls12<ark_bls12_381::Config> as Pairing>::G1;
    type G2 = <Bls12<ark_bls12_381::Config> as Pairing>::G2;
    type E = Bls12_381;

    #[test]
    fn dlog_test() {
        // prove that y = g^x
        let rng = &mut test_rng();
        let pk = ProverKey::<Bls12_381>::setup(rng);

        let x = Fr::rand(rng);
        let y = G1::generator() * x;

        let (com_x, r_x) = pk.commit_fr2(&x, rng);

        // prove
        let theta = G1::generator() * r_x;

        // verify
        // check 1 and check 2 ignored
        // check 3
        let lhs = E::pairing(G1::generator(), com_x[0]);
        let rhs = E::pairing(y, pk.v[0]) + E::pairing(theta, pk.v1[0]);
        assert_eq!(lhs, rhs);

        // check 4
        let lhs = E::pairing(G1::generator(), com_x[1]);
        let rhs = E::pairing(y, pk.v[1]) + E::pairing(theta, pk.v1[1]);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn ppe_test() {
        //prove that e(A,B).e(F,D).e(C,H) = T
        let rng = &mut test_rng();
        let pk = ProverKey::<Bls12_381>::setup(rng);

        let a = G1::rand(rng); //witness
        let b = G2::rand(rng); //witness
        let f = G1::rand(rng); //statement
        let d = G2::rand(rng); //witness
        let c = f; //witness
        let h = d; //statement
        let t = E::pairing(a, b) + E::pairing(f, d) + E::pairing(c, h);

        let (com_a, r_a) = pk.commit_g1(&a, rng);
        let (com_b, r_b) = pk.commit_g2(&b, rng);
        let (com_d, r_d) = pk.commit_g2(&d, rng);
        let (com_c, r_c) = pk.commit_g1(&c, rng);

        let (theta, pi) = pk.prove_ppe(
            rng,
            Some((&a, &r_a, &b, &r_b)),
            &[(&f, &r_d)],
            &[(&r_c, &h)],
        );

        assert!(pk.verify_ppe(
            Some((&com_a, &com_b)),
            &[(&f, &com_d)],
            &[(&com_c, &h)],
            t,
            &theta,
            &pi
        ));

        // UNROLLED version
        // prove
        let mut tt = [[Fr::zero(); 2]; 2];
        for i in 0..2 {
            for j in 0..2 {
                tt[i][j] = Fr::rand(rng);
            }
        }

        let mut rs = [[Fr::zero(); 2]; 2];
        for i in 0..2 {
            for j in 0..2 {
                rs[i][j] = r_a[i] * r_b[j];
            }
        }

        let mut theta = [[G1::generator(); 2]; 2];
        let mut pi = [[G2::generator(); 2]; 2];

        theta[0][0] = pk.u1[0] * tt[0][0] + pk.u2[0] * tt[1][0];
        theta[1][0] = pk.u1[0] * tt[0][1] + pk.u2[0] * tt[1][1];
        theta[0][1] = pk.u1[1] * tt[0][0] + pk.u2[1] * tt[1][0] + f * r_d[0] + a * r_b[0];
        theta[1][1] = pk.u1[1] * tt[0][1] + pk.u2[1] * tt[1][1] + f * r_d[1] + a * r_b[1];

        pi[0][0] = pk.v1[0] * (rs[0][0] - tt[0][0]) + pk.v2[0] * (rs[0][1] - tt[0][1]);
        pi[1][0] = pk.v1[0] * (rs[1][0] - tt[1][0]) + pk.v2[0] * (rs[1][1] - tt[1][1]);
        pi[0][1] = h * r_c[0]
            + b * r_a[0]
            + pk.v1[1] * (rs[0][0] - tt[0][0])
            + pk.v2[1] * (rs[0][1] - tt[0][1]);
        pi[1][1] = h * r_c[1]
            + b * r_a[1]
            + pk.v1[1] * (rs[1][0] - tt[1][0])
            + pk.v2[1] * (rs[1][1] - tt[1][1]);

        // check 1
        let lhs = E::pairing(com_a[0], com_b[0]);
        let rhs = E::pairing(theta[0][0], pk.v1[0])
            + E::pairing(theta[1][0], pk.v2[0])
            + E::pairing(pk.u1[0], pi[0][0])
            + E::pairing(pk.u2[0], pi[1][0]);
        assert_eq!(lhs, rhs);

        // check 2
        let lhs = E::pairing(com_c[0], h) + E::pairing(com_a[0], com_b[1]);
        let rhs = E::pairing(pk.u1[0], pi[0][1])
            + E::pairing(pk.u2[0], pi[1][1])
            + E::pairing(theta[0][0], pk.v1[1])
            + E::pairing(theta[1][0], pk.v2[1]);
        assert_eq!(lhs, rhs);

        // check 3
        let lhs = E::pairing(f, com_d[0]) + E::pairing(com_a[1], com_b[0]);
        let rhs = E::pairing(theta[0][1], pk.v1[0])
            + E::pairing(theta[1][1], pk.v2[0])
            + E::pairing(pk.u1[1], pi[0][0])
            + E::pairing(pk.u2[1], pi[1][0]);
        assert_eq!(lhs, rhs);

        // check 4
        let lhs =
            E::pairing(f, com_d[1]) + E::pairing(com_c[1], h) + E::pairing(com_a[1], com_b[1]);
        let rhs = E::pairing(pk.u1[1], pi[0][1])
            + E::pairing(pk.u2[1], pi[1][1])
            + E::pairing(theta[0][1], pk.v1[1])
            + E::pairing(theta[1][1], pk.v2[1])
            + t;

        assert_eq!(lhs, rhs);
    }
}
