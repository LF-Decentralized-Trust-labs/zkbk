use crate::gro15::{flipped, standard};
use crate::vouch::params::PublicParams;
use crate::vouch::vouch::Vouch;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_std::{rand::Rng, One};

// Re-export SchnorrProof from flipped since it's specific to that key
pub use crate::gro15::flipped::SchnorrProof;

/// The credential stored by the User (contains their secret key)
#[derive(Clone, Debug)]
pub struct Credential<E: Pairing> {
    pub v_u: E::G2,                            // User Public Key (G2)
    pub com_att: E::G2,                        // Commitment to attributes
    pub sigma: standard::Signature<E>,         // Issuer's signature
    pub v_u_sk: Option<flipped::SecretKey<E>>, // User Secret Key (Optional, non-zero/valid only for user)
}

impl<E: Pairing> Credential<E> {
    pub fn issue<R: Rng>(
        pp: &PublicParams<E>,
        issuer_sk: &standard::SecretKey<E>,
        user_vk: &flipped::VerificationKey<E>,
        user_proof: &SchnorrProof<E>,
        attributes: &[E::ScalarField],
        rng: &mut R,
    ) -> Option<Self> {
        // I verifies pi_vU using Flipped Verification Key logic
        // The user_proof proves knowledge of sk corresponding to user_vk.v
        // Using flipped::VerificationKey::verify_knowledge
        if !user_vk.verify_knowledge(&pp.flipped_params, user_proof) {
            return None;
        }

        // Compute polynomial f_att(X)
        let poly = compute_polynomial(attributes);

        // Compute KZG commitment com_att = h^{f_att(tau)}
        // Using CRS in G2
        let com_att = pp.commit_g2(&poly);

        // I signs (V_U, com_att) using Gro15
        // V_U is user_vk.v (in G2)
        let sig = issuer_sk.sign(
            &pp.gro15_params,
            &user_vk.v, // V_U is in G2
            &com_att,   // com_att is in G2
            rng,
        );

        // Return credential with no Secret Key (Issuer doesn't know it)
        Some(Credential {
            v_u: user_vk.v,
            com_att,
            sigma: sig,
            v_u_sk: None,
        })
    }

    pub fn vouch<R: Rng>(
        &self,
        pp: &PublicParams<E>,
        attributes: &[E::ScalarField], // The full attribute set user knows
        idx: &[usize],                 // Indices to reveal
        statement: &E::ScalarField,    // st
        rng: &mut R,
    ) -> Vouch<E> {
        // 1. U computes flipped Gro15 on (M1, M2)
        // M1 = g^st (in G1)
        let m1 = pp.gro15_params.g * statement;

        // M2 = g^{\prod_{i \in idx} (tau - att[i])}
        // Extract subset of attributes
        let mut subset_poly = DensePolynomial::from_coefficients_vec(vec![E::ScalarField::one()]);
        let mut revealed_vals = Vec::new();

        for &i in idx {
            if i >= attributes.len() {
                panic!("Index out of bounds");
            }
            let att = attributes[i];
            revealed_vals.push(att);
            let term = DensePolynomial::from_coefficients_vec(vec![-att, E::ScalarField::one()]);
            subset_poly = &subset_poly * &term;
        }

        let m2 = pp.commit_g1(&subset_poly);

        // Sign (m1, m2) using User Sk (v_U)
        // Use encapsulated SecretKey
        let user_sk = self
            .v_u_sk
            .as_ref()
            .expect("User Secret Key missing in Credential");
        let sigma_vouch = user_sk.sign(&pp.flipped_params, &m1, &m2, rng);

        Vouch {
            v_u: self.v_u,
            com_att: self.com_att,
            sigma_cred: self.sigma.clone(),
            sigma_vouch,
            revealed_indices: idx.to_vec(),
            revealed_values: revealed_vals,
        }
    }
}

pub fn compute_polynomial<F: PrimeField>(attributes: &[F]) -> DensePolynomial<F> {
    // f(X) = \prod (X - att[i])
    // Start with poly = 1
    let mut poly = DensePolynomial::from_coefficients_vec(vec![F::one()]);

    for att in attributes {
        // (X - att)
        let term = DensePolynomial::from_coefficients_vec(vec![-*att, F::one()]);
        poly = &poly * &term;
    }
    poly
}
