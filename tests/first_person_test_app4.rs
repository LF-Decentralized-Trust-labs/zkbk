use std::borrow::Borrow;
use rand_chacha::rand_core::SeedableRng;
use ark_ff::{*};
use ark_bw6_761::{*};
use ark_r1cs_std::prelude::*;
use ark_std::*;
use ark_relations::r1cs::*;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_ec::*;

use zkbk::{record_commitment, prf};
use zkbk::record_commitment::pedersen::{*, constraints::*};
use zkbk::prf::{*, constraints::*};
use zkbk::utils;
use zkbk::signature::{schnorr, schnorr::constraints::*, *};
use zkbk::random_oracle::{RandomOracle, blake2s::RO};

use ark_ed_on_bw6_761::constraints::EdwardsVar as JubJubVar;
use ark_ed_on_bw6_761::EdwardsProjective as JubJub;

pub type ConstraintF = ark_bw6_761::Fr;
pub type H = prf::config::ed_on_bw6_761::Hash;
pub type HG = prf::config::ed_on_bw6_761::HashGadget;
pub type S = schnorr::Schnorr<JubJub>;
pub type SVar = schnorr::constraints::PublicKeyVar<JubJub, JubJubVar>;

type MsgVar = Vec<UInt8<ConstraintF>>;

pub struct IssuerCircuit {
    pub nullifier_prf_instance: JZPRFInstance<H>, // PRF(issuer_sk, user_public_key)
    pub user_record: JZRecord<3, 4, ark_bls12_377::Config>, // (sk, null, h_att)
    pub schnorr_parameters: <S as SignatureScheme>::Parameters,
    pub user_secret_key: <S as SignatureScheme>::SecretKey,
    pub user_public_key: <S as SignatureScheme>::PublicKey,
    pub issuer_secret_key: <S as SignatureScheme>::SecretKey,
    pub issuer_public_key: <S as SignatureScheme>::PublicKey,
    pub certification: <S as SignatureScheme>::Signature,
    pub attestation: <S as SignatureScheme>::Signature,
    pub statement: ConstraintF,
}

fn generate_schnorr_verification_constraints<S: SignatureScheme, SG: SigVerifyGadget<S, ConstraintF>>(
    cs: ConstraintSystemRef<ConstraintF>,
    schnorr_parameters: &<S as SignatureScheme>::Parameters,
    certification: &<S as SignatureScheme>::Signature,
    issuer_public_key: &<S as SignatureScheme>::PublicKey,
    message: &[u8],
) -> (SG::PublicKeyVar, MsgVar) {
    let parameters_var = SG::ParametersVar::new_constant(cs.clone(), schnorr_parameters).unwrap();
    let signature_var = SG::SignatureVar::new_witness(cs.clone(), || Ok(certification)).unwrap();
    let pk_var = SG::PublicKeyVar::new_witness(cs.clone(), || Ok(issuer_public_key)).unwrap();
    let mut msg_var = Vec::new();
    for i in 0..message.len() {
        msg_var.push(UInt8::new_witness(cs.clone(), || Ok(&message[i])).unwrap())
    }
    let valid_sig_var = SG::verify(&parameters_var, &pk_var, &msg_var, &signature_var).unwrap();

    valid_sig_var.enforce_equal(&Boolean::<ConstraintF>::TRUE).unwrap();

    (pk_var, msg_var)
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

        // issuer's signature
        let (issuer_pk_var, issuer_signature_msg_var) = generate_schnorr_verification_constraints::<
            schnorr::Schnorr<JubJub>,
            SchnorrSignatureVerifyGadget<JubJub, JubJubVar>,
        >(cs.clone(), &self.schnorr_parameters, &self.certification, &self.issuer_public_key, &utils::serialize(&user_record_com.x));
        let issuer_pk_var: SVar = issuer_pk_var.into();

        // user's signature
        let statement_encoded = encode_statement(&self.statement);
        let (user_pk_var, user_signature_msg_var) = generate_schnorr_verification_constraints::<
            schnorr::Schnorr<JubJub>,
            SchnorrSignatureVerifyGadget<JubJub, JubJubVar>,
        >(cs.clone(), &self.schnorr_parameters, &self.attestation, &self.user_public_key, &statement_encoded);
        let user_pk_var: SVar = user_pk_var.into();

        //--------------- Public Variable ------------------

        // make the issuer public key a public variable
        let public_var_issuer_public_key_x = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "issuer_public_key_x"), 
            || { Ok(self.issuer_public_key.x) },
        ).unwrap();
        issuer_pk_var.pub_key.x.enforce_equal(&public_var_issuer_public_key_x)?;

        let statement_digest_var = ark_ed_on_bw6_761::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "statement_digest"), 
            || { Ok(self.statement) },
        ).unwrap();


        //--------------- Binding the three ------------------

        // message signed by the user
        let statement_digest_var_bytes = statement_digest_var.to_bytes_le().unwrap();
        for i in 0..user_signature_msg_var.len() {
            statement_digest_var_bytes[i].enforce_equal(&user_signature_msg_var[i])?;
        }

        // output of ped com is the input msg being signed
        let user_record_com_affine_x_bytes = user_record_var
            .commitment
            .to_affine()
            .unwrap()
            .x
            .to_bytes_le()
            .unwrap();
        for i in 0..user_record_com_affine_x_bytes.len() {
            user_record_com_affine_x_bytes[i].enforce_equal(&issuer_signature_msg_var[i])?;
        }

        // collect all the bytes from pk encoding
        let user_pk_encoded = encode_public_key(&self.user_public_key);
        let mut pubkey_byte_vars: Vec::<UInt8<ConstraintF>> = Vec::new();
        for i in 0..user_pk_encoded.len() {
            pubkey_byte_vars.push(UInt8::new_witness(cs.clone(), || Ok(&user_pk_encoded[i])).unwrap())
        }

        // check if it matches the pubkey from schnorr
        let user_pk_var_serialization = user_pk_var.pub_key.x.to_bytes_le().unwrap();
        for i in 0..pubkey_byte_vars.len() {
            pubkey_byte_vars[i].enforce_equal(&user_pk_var_serialization[i])?;
        }

        // the input to nullifier PRF is the public key
        for (i, byte_var) in nullifier_prf_instance_var.input_var.iter().enumerate() {
            byte_var.enforce_equal(&pubkey_byte_vars[i])?;
        }

        // the pubkey is at index 0 of the user record
        for (i, byte_var) in user_record_var.fields[0].iter().enumerate() {
            byte_var.enforce_equal(&pubkey_byte_vars[i])?;
        }
        // the nullifier is at index 1 of the user record
        for (i, byte_var) in user_record_var.fields[1].iter().enumerate() {
            byte_var.enforce_equal(&nullifier_prf_instance_var.output_var[i])?;
        }

        Ok(())
    }
}

fn compute_nullifier(prf_instance: &JZPRFInstance<H>) -> Vec<u8> {
    prf_instance.evaluate().iter().take(32).cloned().collect()
}

fn encode_public_key(pk: &<S as SignatureScheme>::PublicKey) -> Vec<u8> {
    utils::serialize(pk).iter().take(32).cloned().collect()
}

fn encode_statement(statement: &ConstraintF) -> Vec<u8> {
    statement.into_bigint().to_bytes_le().iter().take(32).cloned().collect()
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
    let user_pk_encoded = encode_public_key(&user_public_key);
    let user_sk_encoded = utils::serialize(&user_secret_key.secret_key);

    let nullifier_prf_instance = JZPRFInstance::new(
        &prf_params,
        &user_pk_encoded,
        &user_sk_encoded
    );
    let nullifier: Vec<u8> = compute_nullifier(&nullifier_prf_instance);

    let merkle_root = vec![10u8; 32]; // placeholder for now

    let fields: [Vec<u8>; 3] = [ user_pk_encoded, nullifier, merkle_root ];

    let user_record = JZRecord::<3, 4, ark_bls12_377::Config>::new(&crs, &fields);
    let user_record_com = user_record.commitment().into_affine();

    let message = utils::serialize(&user_record_com.x);
    let certification = S::sign(
        &schnorr_parameters,
        &issuer_secret_key,
        &message,
        &mut rng
    ).unwrap();
    assert!(S::verify(&schnorr_parameters, &issuer_public_key, &message, &certification).unwrap());

    let statement_digest = RO::evaluate(&(), &("Hart is amazing!").as_bytes()).unwrap();
    let statement = ConstraintF::from(
        BigInt::<6>::from_bits_le(
            utils::bytes_to_bits(&statement_digest).as_slice()
        )
    );
    let attestation = S::sign(
        &schnorr_parameters,
        &user_secret_key,
        &statement_digest,
        &mut rng
    ).unwrap();
    assert!(S::verify(&schnorr_parameters, &user_public_key, &statement_digest, &attestation).unwrap());

    IssuerCircuit {
        nullifier_prf_instance,
        user_record,
        issuer_public_key,
        issuer_secret_key,
        user_public_key,
        user_secret_key,
        certification,
        schnorr_parameters,
        attestation,
        statement
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

    let public_input = [ circuit.issuer_public_key.x, circuit.statement ];

    let now = std::time::Instant::now();
    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();
    let elapsed = now.elapsed();
    println!("Prover time: {:.2?}", elapsed);

    let valid_proof = Groth16::<BW6_761>::verify(&vk, &public_input, &proof).unwrap();
    assert!(valid_proof);

}