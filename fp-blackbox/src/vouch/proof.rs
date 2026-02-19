use crate::gro15::{flipped, standard};
use crate::gs08::ProverKey;
use crate::vouch::credential::Credential;
use crate::vouch::params::PublicParams;
use crate::vouch::vouch::Vouch;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ff::Zero;
use ark_std::rand::Rng;

/// A Groth-Sahai proof of a Vouch
#[derive(Clone, Debug)]
pub struct Proof<E: Pairing> {
    // Commitments to witnesses
    pub com_r: [E::G1; 2],
    pub com_s: [E::G2; 2],
    pub com_t1: [E::G2; 2],
    pub com_t2: [E::G2; 2],

    pub com_vu: [E::G2; 2],
    pub com_att: [E::G2; 2],
    pub com_pi_idx: [E::G2; 2],

    pub com_rst: [E::G2; 2],
    pub com_sst: [E::G1; 2],
    pub com_tst1: [E::G1; 2],
    pub com_tst2: [E::G1; 2],

    // Proofs for equations
    pub proof_1_theta: [[E::G1; 2]; 2],
    pub proof_1_pi: [[E::G2; 2]; 2],

    pub proof_2_theta: [[E::G1; 2]; 2],
    pub proof_2_pi: [[E::G2; 2]; 2],

    pub proof_3_theta: [[E::G1; 2]; 2],
    pub proof_3_pi: [[E::G2; 2]; 2],

    pub proof_4_theta: [[E::G1; 2]; 2],
    pub proof_4_pi: [[E::G2; 2]; 2],

    pub proof_5_theta: [[E::G1; 2]; 2],
    pub proof_5_pi: [[E::G2; 2]; 2],

    pub proof_6_theta: [[E::G1; 2]; 2],
    pub proof_6_pi: [[E::G2; 2]; 2],

    pub proof_7_theta: [[E::G1; 2]; 2],
    pub proof_7_pi: [[E::G2; 2]; 2],
}

impl<E: Pairing> Proof<E> {
    #[allow(clippy::too_many_arguments)]
    pub fn prove<R: Rng>(
        pp: &PublicParams<E>,
        pk: &ProverKey<E>,
        vouch: &Vouch<E>,
        credential: &Credential<E>,
        user_vk: &flipped::VerificationKey<E>,
        m2_poly_val: &E::G1,
        kzg_pi: &E::G2,
        rng: &mut R,
    ) -> Self {
        // Witnesses
        let r = credential.sigma.r;
        let s = credential.sigma.s;
        let t1 = credential.sigma.t1;
        let t2 = credential.sigma.t2;

        // let vu = user_vk.v;
        let com_att = credential.com_att;

        // Vouch witnesses
        let rst = vouch.sigma_vouch.r;
        let sst = vouch.sigma_vouch.s;
        let tst1 = vouch.sigma_vouch.t1;
        let tst2 = vouch.sigma_vouch.t2;

        // Commitments
        let (com_r, r_r) = pk.commit_g1(&r, rng);
        let (com_s, r_s) = pk.commit_g2(&s, rng);
        let (com_t1, r_t1) = pk.commit_g2(&t1, rng);
        let (com_t2, r_t2) = pk.commit_g2(&t2, rng);

        let (com_vu, r_vu) = pk.commit_g2(&user_vk.v, rng);
        let (com_att, r_com_att) = pk.commit_g2(&com_att, rng);
        let (com_pi_idx, r_pi_idx) = pk.commit_g2(kzg_pi, rng);

        let (com_rst, r_rst) = pk.commit_g2(&rst, rng);
        let (com_sst, r_sst) = pk.commit_g1(&sst, rng);
        let (com_tst1, r_tst1) = pk.commit_g1(&tst1, rng);
        let (com_tst2, r_tst2) = pk.commit_g1(&tst2, rng);

        // Eq 1: e(R, S) = e(g, Y1) * e(VI, h)
        // e(R, S) = T.
        let proof_1 = pk.prove_ppe(rng, Some((&r, &r_r, &s, &r_s)), &[], &[]);

        // Eq 2: e(R, T1) = e(g, VU) * e(VI, Y1)
        // e(R, T1) + e(-g, VU) = T.
        let neg_g = -pp.gro15_params.g;
        let proof_2 = pk.prove_ppe(rng, Some((&r, &r_r, &t1, &r_t1)), &[(&neg_g, &r_vu)], &[]);

        // Eq 3: e(R, T2) = e(g, com_att) * e(VI, Y2)
        // e(R, T2) + e(-g, com_att) = T
        let proof_3 = pk.prove_ppe(
            rng,
            Some((&r, &r_r, &t2, &r_t2)),
            &[(&neg_g, &r_com_att)],
            &[],
        );

        // Eq 4: e(M2, pi_idx) = e(g, com_att)
        // e(M2, pi_idx) + e(-g, com_att) = 0
        let proof_4 = pk.prove_ppe(
            rng,
            None,
            &[(&(*m2_poly_val), &r_pi_idx), (&neg_g, &r_com_att)],
            &[],
        );

        // Eq 5: e(Sst, Rst) = e(W1, h) * e(g, VU)
        // e(Sst, Rst) + e(-g, VU) = T
        let proof_5 = pk.prove_ppe(
            rng,
            Some((&sst, &r_sst, &rst, &r_rst)),
            &[(&neg_g, &r_vu)],
            &[],
        );

        // Eq 6: e(Tst1, Rst) = e(M1, h) * e(W1, VU)
        // e(Tst1, Rst) + e(-W1, VU) = T
        let neg_w1 = -pp.flipped_params.w1;
        let proof_6 = pk.prove_ppe(
            rng,
            Some((&tst1, &r_tst1, &rst, &r_rst)),
            &[(&neg_w1, &r_vu)],
            &[],
        );

        // Eq 7: e(Tst2, Rst) = e(M2, h) * e(W2, VU)
        // e(Tst2, Rst) + e(-W2, VU) = T
        let neg_w2 = -pp.flipped_params.w2;
        let proof_7 = pk.prove_ppe(
            rng,
            Some((&tst2, &r_tst2, &rst, &r_rst)),
            &[(&neg_w2, &r_vu)],
            &[],
        );

        Proof {
            com_r,
            com_s,
            com_t1,
            com_t2,
            com_vu,
            com_att,
            com_pi_idx,
            com_rst,
            com_sst,
            com_tst1,
            com_tst2,
            proof_1_theta: proof_1.0,
            proof_1_pi: proof_1.1,
            proof_2_theta: proof_2.0,
            proof_2_pi: proof_2.1,
            proof_3_theta: proof_3.0,
            proof_3_pi: proof_3.1,
            proof_4_theta: proof_4.0,
            proof_4_pi: proof_4.1,
            proof_5_theta: proof_5.0,
            proof_5_pi: proof_5.1,
            proof_6_theta: proof_6.0,
            proof_6_pi: proof_6.1,
            proof_7_theta: proof_7.0,
            proof_7_pi: proof_7.1,
        }
    }

    pub fn verify(
        &self,
        pp: &PublicParams<E>,
        pk: &ProverKey<E>,
        issuer_vk: &standard::VerificationKey<E>,
        statement: &E::ScalarField,
        m2_val: &E::G1,
    ) -> bool {
        // Reconstruct constants
        let g = pp.gro15_params.g;
        let h = pp.gro15_params.h;
        let y1 = pp.gro15_params.y1;
        let y2 = pp.gro15_params.y2;
        let vi = issuer_vk.v;
        let w1 = pp.flipped_params.w1;
        let w2 = pp.flipped_params.w2;
        let m1 = g * statement;
        let m2 = *m2_val;

        // Targets
        let t1 = E::pairing(g, y1) + E::pairing(vi, h);
        let t2 = E::pairing(vi, y1);
        let t3 = E::pairing(vi, y2);
        let t4 = PairingOutput::zero();
        let t5 = E::pairing(w1, h);
        let t6 = E::pairing(m1, h);
        let t7 = E::pairing(m2, h);

        let ok1 = pk.verify_ppe(
            Some((&self.com_r, &self.com_s)),
            &[],
            &[],
            t1,
            &self.proof_1_theta,
            &self.proof_1_pi,
        );

        let ok2 = pk.verify_ppe(
            Some((&self.com_r, &self.com_t1)),
            &[(&(-g), &self.com_vu)],
            &[],
            t2,
            &self.proof_2_theta,
            &self.proof_2_pi,
        );

        let ok3 = pk.verify_ppe(
            Some((&self.com_r, &self.com_t2)),
            &[(&(-g), &self.com_att)],
            &[],
            t3,
            &self.proof_3_theta,
            &self.proof_3_pi,
        );

        let ok4 = pk.verify_ppe(
            None,
            &[(&m2, &self.com_pi_idx), (&(-g), &self.com_att)],
            &[],
            t4,
            &self.proof_4_theta,
            &self.proof_4_pi,
        );

        let ok5 = pk.verify_ppe(
            Some((&self.com_sst, &self.com_rst)),
            &[(&(-g), &self.com_vu)],
            &[],
            t5,
            &self.proof_5_theta,
            &self.proof_5_pi,
        );

        let ok6 = pk.verify_ppe(
            Some((&self.com_tst1, &self.com_rst)),
            &[(&(-w1), &self.com_vu)],
            &[],
            t6,
            &self.proof_6_theta,
            &self.proof_6_pi,
        );

        let ok7 = pk.verify_ppe(
            Some((&self.com_tst2, &self.com_rst)),
            &[(&(-w2), &self.com_vu)],
            &[],
            t7,
            &self.proof_7_theta,
            &self.proof_7_pi,
        );

        ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7
    }
}
