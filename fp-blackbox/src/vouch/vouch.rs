use crate::gro15::{flipped, standard};
use crate::vouch::params::PublicParams;
use ark_ec::pairing::Pairing;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_std::One;

/// The Vouch Proof presented to a Verifier
#[derive(Clone, Debug)]
pub struct Vouch<E: Pairing> {
    pub v_u: E::G2,
    pub com_att: E::G2,
    pub sigma_cred: standard::Signature<E>,
    pub sigma_vouch: flipped::Signature<E>,
    // Indices of attributes revealed
    pub revealed_indices: Vec<usize>,
    // Values of attributes revealed
    pub revealed_values: Vec<E::ScalarField>,
}

impl<E: Pairing> Vouch<E> {
    pub fn verify(
        &self,
        pp: &PublicParams<E>,
        issuer_vk: &standard::VerificationKey<E>,
        statement: &E::ScalarField,
    ) -> bool {
        // 1. Verify Issuer Signature on Credential
        // Msg: (V_U, com_att)
        let valid_cred =
            issuer_vk.verify(&pp.gro15_params, &self.v_u, &self.com_att, &self.sigma_cred);

        if !valid_cred {
            return false;
        }

        // 2. Compute M1, M2 for Vouch
        // M1 = g^st
        let m1 = pp.gro15_params.g * statement;

        // M2 = g^{P_subset(tau)}
        // Reconstruct polynomial from revealed values
        let mut subset_poly = DensePolynomial::from_coefficients_vec(vec![E::ScalarField::one()]);
        for &val in &self.revealed_values {
            let term = DensePolynomial::from_coefficients_vec(vec![-val, E::ScalarField::one()]);
            subset_poly = &subset_poly * &term;
        }
        let m2 = pp.commit_g1(&subset_poly);

        // 3. Verify User Signature
        // Vk: proof.v_u (in G2)
        // Msg: (M1, M2) in G1
        // User Vk is essentially proof.v_u wrapped
        let user_vk_struct = flipped::VerificationKey { v: self.v_u };
        let valid_vouch = user_vk_struct.verify(&pp.flipped_params, &m1, &m2, &self.sigma_vouch);

        valid_vouch
    }
}
