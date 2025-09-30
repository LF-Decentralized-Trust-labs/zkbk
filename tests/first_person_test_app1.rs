use std::borrow::Borrow;
use rand_chacha::rand_core::SeedableRng;
use ark_ec::{*};
use ark_ff::{*};
use ark_bw6_761::{*};
use ark_r1cs_std::prelude::*;
use ark_std::*;
use ark_relations::r1cs::*;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_snark::SNARK;

use zkbk::{record_commitment, prf};
use zkbk::record_commitment::pedersen::{*, constraints::*};
use zkbk::prf::{*, constraints::*};

pub type ConstraintF = ark_bw6_761::Fr;
pub type H = prf::config::ed_on_bw6_761::Hash;
pub type HG = prf::config::ed_on_bw6_761::HashGadget;

pub struct IssuerCircuit {
    pub nullifier_prf_instance: JZPRFInstance<H>, // PRF(issuer_sk, user_public_key)
    pub user_record: JZRecord<3, 4, ark_bls12_377::Config>, // (sk, null, h_att)
    pub user_secret_key: JZRecord<1, 4, ark_bls12_377::Config>, // (sk), whose com is user_pub_key
}

impl ConstraintSynthesizer<ConstraintF> for IssuerCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<()> {

        //---------------------- PRF of user pub key -------------------------
        let params_var = JZPRFParamsVar::<H, HG, ConstraintF>::new_constant(
            cs.clone(),
            &self.nullifier_prf_instance.params
        ).unwrap();

        let nullifier_prf_instance_var = JZPRFInstanceVar::<ConstraintF>::new_witness(
            cs.clone(),
            || Ok(self.nullifier_prf_instance)
        ).unwrap();

        prf::constraints::generate_constraints(cs.clone(), &params_var, &nullifier_prf_instance_var);

        //--------------- Pedersen Commitment for user record ------------------

        let crs_var = JZPedCommitmentParamsVar::<3, ark_bls12_377::Config>::new_constant(
            cs.clone(),
            self.user_record.crs.clone()
        ).unwrap();

        let user_record_var = JZRecordVar::<3, ark_bls12_377::Config, ark_bls12_377::Fq>::new_witness(
            cs.clone(),
            || Ok(self.user_record.borrow())
        ).unwrap();

        // let user_record = self.user_record.borrow();
        // let user_record_com = user_record.commitment().into_affine();

        record_commitment::pedersen::constraints::generate_constraints(
            cs.clone(),
            &crs_var,
            &user_record_var
        ).unwrap();

        //--------------- Pedersen Commitment for user record ------------------

        let sub_crs_var = JZPedCommitmentParamsVar::<1, ark_bls12_377::Config>::new_constant(
            cs.clone(),
            self.user_secret_key.crs.clone()
        ).unwrap();

        let user_secret_key_var = JZRecordVar::<1, ark_bls12_377::Config, ark_bls12_377::Fq>::new_witness(
            cs.clone(),
            || Ok(self.user_secret_key.borrow())
        ).unwrap();

        let user_secret_key = self.user_secret_key.borrow();
        let user_public_key = user_secret_key.commitment().into_affine();

        let public_var_user_public_key_x = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "public_key_x"), 
            || { Ok(user_public_key.x) },
        ).unwrap();

        let public_var_user_public_key_y = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "public_key_y"), 
            || { Ok(user_public_key.y) },
        ).unwrap();

        record_commitment::pedersen::constraints::generate_constraints(
            cs.clone(),
            &sub_crs_var,
            &user_secret_key_var
        ).unwrap();

        // compute the affine var from the projective var
        let user_public_key_affine = user_secret_key_var.commitment.to_affine().unwrap();
        user_public_key_affine.x.enforce_equal(&public_var_user_public_key_x)?;
        user_public_key_affine.y.enforce_equal(&public_var_user_public_key_y)?;

        //--------------- Binding the three ------------------

        let user_secret_key_com_affine = user_secret_key_var.commitment.to_affine().unwrap();
        // just compare the x-coordinate...that's what compressed mode stores anyways
        // see ark_ec::models::short_weierstrass::GroupAffine::to_bytes
        let mut pubkey_byte_vars: Vec::<UInt8<ConstraintF>> = Vec::new();
        pubkey_byte_vars.extend_from_slice(&user_secret_key_com_affine.x.to_bytes_le()?);

        // prove ownership of the coin. Does sk correspond to coin's pk?
        for (i, byte_var) in pubkey_byte_vars.iter().enumerate() {
            byte_var.enforce_equal(&nullifier_prf_instance_var.input_var[i])?;
        }

        // prove ownership of the coin. Does sk correspond to coin's pk?
        for (i, byte_var) in user_record_var.fields[1].iter().enumerate() {
            byte_var.enforce_equal(&nullifier_prf_instance_var.output_var[i])?;
        }

        Ok(())
    }
}

fn compute_nullifier(prf_instance: &JZPRFInstance<H>) -> Vec<u8> {
    prf_instance.evaluate().iter().take(32).cloned().collect()
}

fn setup_witness() -> IssuerCircuit {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let prf_params = JZPRFParams::<H>::trusted_setup(&mut rng);
    let crs = JZPedCommitmentParams::<3, 4, ark_bls12_377::Config>::trusted_setup(&mut rng);
    let sub_crs = JZPedCommitmentParams {
        crs_coefficients: crs.crs_coefficients.iter().take(1).cloned().collect() 
    };

    let alice_sk = [20u8; 32];
    let issuer_sk = [30u8; 32];

    let user_secret_key = JZRecord::<1, 4, ark_bls12_377::Config>::new(&sub_crs, &[alice_sk.to_vec()]);
    let user_public_key = user_secret_key.commitment().into_affine();
    let user_public_key_bytes = user_public_key.x.into_bigint().to_bytes_le();

    let nullifier_prf_instance = JZPRFInstance::new(&prf_params, &user_public_key_bytes, &issuer_sk);
    let nullifier: Vec<u8> = compute_nullifier(&nullifier_prf_instance);

    let merkle_root = vec![10u8; 32]; // placeholder for now

    let fields: [Vec<u8>; 3] = [ alice_sk.to_vec(), nullifier, merkle_root ];

    let user_record = JZRecord::<3, 4, ark_bls12_377::Config>::new(&crs, &fields);

    IssuerCircuit { nullifier_prf_instance, user_record, user_secret_key }
}

#[allow(dead_code)]
fn circuit_setup() -> (ProvingKey<BW6_761>, VerifyingKey<BW6_761>) {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let circuit = setup_witness();

    let (pk, vk) = Groth16::<BW6_761>::
        circuit_specific_setup(circuit, &mut rng)
        .unwrap();

    (pk, vk)
}

#[test]
fn spending() {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let (pk, vk) = circuit_setup();

    let circuit = setup_witness();

    let _record_com = circuit.user_record.commitment().into_affine();
    let user_pk = circuit.user_secret_key.commitment().into_affine();

    let public_input = [ user_pk.x, user_pk.y ];

    let now = std::time::Instant::now();
    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();
    let elapsed = now.elapsed();
    println!("Prover time: {:.2?}", elapsed);

    let valid_proof = Groth16::<BW6_761>::verify(&vk, &public_input, &proof).unwrap();
    assert!(valid_proof);

}