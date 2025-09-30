use std::borrow::Borrow;
use rand_chacha::rand_core::SeedableRng;
use ark_ff::{*};
use ark_bw6_761::{*};
use ark_r1cs_std::prelude::*;
use ark_std::*;
use ark_relations::r1cs::*;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_ec::CurveGroup;

use zkbk::{record_commitment, prf};
use zkbk::record_commitment::pedersen::{*, constraints::*};
use zkbk::prf::{*, constraints::*};
use zkbk::utils;
use zkbk::signature::{schnorr, schnorr::constraints::*, *};

use ark_ed_on_bw6_761::constraints::EdwardsVar as JubJubVar;
use ark_ed_on_bw6_761::EdwardsProjective as JubJub;

pub type ConstraintF = ark_bw6_761::Fr;
pub type H = prf::config::ed_on_bw6_761::Hash;
pub type HG = prf::config::ed_on_bw6_761::HashGadget;
pub type S = schnorr::Schnorr<JubJub>;

pub struct IssuerCircuit {
    pub nullifier_prf_instance: JZPRFInstance<H>, // PRF(issuer_sk, user_public_key)
    pub user_record: JZRecord<3, 4, ark_bls12_377::Config>, // (sk, null, h_att)
    pub schnorr_parameters: <S as SignatureScheme>::Parameters,
    pub user_secret_key: <S as SignatureScheme>::SecretKey,
    pub user_public_key: <S as SignatureScheme>::PublicKey,
    pub issuer_secret_key: <S as SignatureScheme>::SecretKey,
    pub issuer_public_key: <S as SignatureScheme>::PublicKey,
    pub certification: <S as SignatureScheme>::Signature,
}

fn generate_schnorr_verification_constraints<S: SignatureScheme, SG: SigVerifyGadget<S, ConstraintF>>(
    cs: ConstraintSystemRef<ConstraintF>,
    schnorr_parameters: &<S as SignatureScheme>::Parameters,
    certification: &<S as SignatureScheme>::Signature,
    issuer_public_key: &<S as SignatureScheme>::PublicKey,
    message: &[u8],
) {
    let parameters_var = SG::ParametersVar::new_constant(cs.clone(), schnorr_parameters).unwrap();
    let signature_var = SG::SignatureVar::new_witness(cs.clone(), || Ok(certification)).unwrap();
    let pk_var = SG::PublicKeyVar::new_witness(cs.clone(), || Ok(issuer_public_key)).unwrap();
    let mut msg_var = Vec::new();
    for i in 0..message.len() {
        msg_var.push(UInt8::new_witness(cs.clone(), || Ok(&message[i])).unwrap())
    }
    let valid_sig_var = SG::verify(&parameters_var, &pk_var, &msg_var, &signature_var).unwrap();

    valid_sig_var.enforce_equal(&Boolean::<ConstraintF>::TRUE).unwrap();
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

        prf::constraints::generate_constraints(
            cs.clone(),
            &params_var,
            &nullifier_prf_instance_var
        );

        //--------------- Pedersen Commitment for user record ------------------

        let crs_var = JZPedCommitmentParamsVar::<3, ark_bls12_377::Config>::new_constant(
            cs.clone(),
            self.user_record.crs.clone()
        ).unwrap();

        let user_record_var = JZRecordVar::<3, ark_bls12_377::Config, ark_bls12_377::Fq>::new_witness(
            cs.clone(),
            || Ok(self.user_record.borrow())
        ).unwrap();

        let user_record_com = self.user_record.commitment().into_affine();

        record_commitment::pedersen::constraints::generate_constraints(
            cs.clone(),
            &crs_var,
            &user_record_var
        ).unwrap();

        //--------------- Schnorr stuff ------------------

        let message = utils::serialize(&user_record_com.x);
        generate_schnorr_verification_constraints::<
            schnorr::Schnorr<JubJub>,
            SchnorrSignatureVerifyGadget<JubJub, JubJubVar>,
        >(cs.clone(), &self.schnorr_parameters, &self.certification, &self.issuer_public_key, &message);


        //--------------- Binding the three ------------------

        let user_pk_encoded: Vec<u8> = utils::serialize(&self.user_public_key).iter().take(32).cloned().collect();
        let mut pubkey_byte_vars: Vec::<UInt8<ConstraintF>> = Vec::new();
        for i in 0..user_pk_encoded.len() {
            pubkey_byte_vars.push(UInt8::new_witness(cs.clone(), || Ok(&user_pk_encoded[i])).unwrap())
        }

        for (i, byte_var) in pubkey_byte_vars.iter().enumerate() {
            byte_var.enforce_equal(&nullifier_prf_instance_var.input_var[i])?;
        }

        // the pubkey is at index 0
        for (i, byte_var) in user_record_var.fields[0].iter().enumerate() {
            byte_var.enforce_equal(&pubkey_byte_vars[i])?;
        }
        // the nullifier is at index 1
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

    // public parameters and CRS objects
    let prf_params = JZPRFParams::<H>::trusted_setup(&mut rng);
    let crs = JZPedCommitmentParams::<3, 4, ark_bls12_377::Config>::trusted_setup(&mut rng);

    let schnorr_parameters = S::setup::<_>(&mut rng).unwrap();
    let (user_public_key, user_secret_key) = S::keygen(&schnorr_parameters, &mut rng).unwrap();
    let (issuer_public_key, issuer_secret_key) = S::keygen(&schnorr_parameters, &mut rng).unwrap();
    let user_pk_encoded: Vec<u8> = utils::serialize(&user_public_key).iter().take(32).cloned().collect();

    let nullifier_prf_instance = JZPRFInstance::new(
        &prf_params,
        &user_pk_encoded,
        &utils::serialize(&issuer_secret_key.secret_key)
    );
    let nullifier: Vec<u8> = compute_nullifier(&nullifier_prf_instance);

    let merkle_root = vec![10u8; 32]; // placeholder for now

    let fields: [Vec<u8>; 3] = [ user_pk_encoded, nullifier, merkle_root ];

    let user_record = JZRecord::<3, 4, ark_bls12_377::Config>::new(&crs, &fields);
    let user_record_com = user_record.commitment().into_affine();

    let message = utils::serialize(&user_record_com.x);
    let certification = S::sign(&schnorr_parameters, &issuer_secret_key, &message, &mut rng).unwrap();
    assert!(S::verify(&schnorr_parameters, &issuer_public_key, &message, &certification).unwrap());

    IssuerCircuit {
        nullifier_prf_instance,
        user_record,
        issuer_public_key,
        issuer_secret_key,
        user_public_key,
        user_secret_key,
        certification,
        schnorr_parameters
    }
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
fn test_issuance() {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let (pk, vk) = circuit_setup();

    let circuit = setup_witness();

    let public_input = [ ];

    let now = std::time::Instant::now();
    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();
    let elapsed = now.elapsed();
    println!("Prover time: {:.2?}", elapsed);

    let valid_proof = Groth16::<BW6_761>::verify(&vk, &public_input, &proof).unwrap();
    assert!(valid_proof);

}