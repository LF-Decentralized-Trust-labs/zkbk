pub mod credential;
pub mod params;
pub mod proof;
pub mod vouch;

#[cfg(test)]
mod tests {
    use super::credential::Credential;
    use super::params::PublicParams;
    use crate::gro15::{flipped, standard};
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_poly::DenseUVPolynomial;

    use ark_std::{test_rng, One, Zero};

    #[test]
    fn test_e2e_vouchable_credentials() {
        let rng = &mut test_rng();
        type E = Bls12_381;
        type Fr = <E as Pairing>::ScalarField;

        // 1. Setup
        let pp = PublicParams::<E>::new(10, rng);

        // 2. Issuer KeyGen
        let (issuer_pk, issuer_sk) = standard::SecretKey::new(&pp.gro15_params, rng);

        // 3. User KeyGen (Part of Issue prep)
        let (user_vk, user_sk) = flipped::SecretKey::new(&pp.flipped_params, rng);
        // Prove knowledge of SK. Now sk is encapsulated.
        let user_proof = user_sk.prove_knowledge(&pp.flipped_params, rng);

        // 4. Issue
        let attributes = vec![Fr::from(10u64), Fr::from(20u64), Fr::from(30u64)];
        let mut cred = Credential::issue(&pp, &issuer_sk, &user_vk, &user_proof, &attributes, rng)
            .expect("Issue failed");

        // Fix the secret key in credential (simulating user local storage)
        cred.v_u_sk = Some(user_sk);

        // 5. Vouch
        // Reval attribute at index 1 (val 20)
        let idx = vec![1];
        let statement = Fr::from(12345u64);
        let proof = cred.vouch(&pp, &attributes, &idx, &statement, rng);

        // 6. Verify
        let valid = proof.verify(&pp, &issuer_pk, &statement);

        assert!(valid, "Vouch verification failed");

        // 7. Test GS Proof
        // Setup GS ProverKey (In practice, part of CRS)
        let pk = crate::gs08::ProverKey::<E>::setup(rng);

        // Compute m2_poly_val (accumulator) for the proof
        // m2 = g^{P_subset(tau)}
        let mut subset_poly =
            ark_poly::univariate::DensePolynomial::from_coefficients_vec(vec![Fr::one()]);
        for &val in &proof.revealed_values {
            let term =
                ark_poly::univariate::DensePolynomial::from_coefficients_vec(vec![-val, Fr::one()]);
            subset_poly = &subset_poly * &term;
        }
        let m2 = pp.commit_g1(&subset_poly);

        let poly = crate::vouch::credential::compute_polynomial(&attributes);
        let q_poly = &poly / &subset_poly;
        let r_poly = &poly - &(&q_poly * &subset_poly);
        assert!(r_poly.is_zero(), "Polynomial division failed");

        let kzg_pi = pp.commit_g2(&q_poly);

        let user_vk_flipped = flipped::VerificationKey { v: cred.v_u };

        let gs_proof = crate::vouch::proof::Proof::prove(
            &pp,
            &pk,
            &proof,
            &cred,
            &user_vk_flipped,
            &m2,
            &kzg_pi,
            rng,
        );

        let valid_gs = gs_proof.verify(&pp, &pk, &issuer_pk, &statement, &m2);

        assert!(valid_gs, "GS Proof verification failed");
    }
}
