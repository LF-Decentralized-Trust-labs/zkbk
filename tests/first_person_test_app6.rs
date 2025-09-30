use std::borrow::Borrow;
use rand_chacha::rand_core::SeedableRng;

use ark_ff::{*};
use ark_bls12_377::{*};
use ark_r1cs_std::prelude::*;
use ark_std::*;
use ark_relations::r1cs::*;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_snark::SNARK;

use zkbk::{record_commitment, vector_commitment, prf};
use zkbk::record_commitment::sha256::{*, constraints::*};
use zkbk::vector_commitment::bytes::sha256::{*, constraints::*};
use zkbk::prf::{*, constraints::*};
use zkbk::signature::{schnorr, schnorr::constraints::*, *};
use zkbk::random_oracle::{RandomOracle, blake2s::RO};
use zkbk::utils;

use ark_ed_on_bls12_377::constraints::EdwardsVar as JubJubVar;
use ark_ed_on_bls12_377::EdwardsProjective as JubJub;

type ConstraintF = ark_bls12_377::Fr;
type H = prf::config::ed_on_bls12_377::Hash;
type HG = prf::config::ed_on_bls12_377::HashGadget;
type S = schnorr::Schnorr<JubJub>;
type SVar = schnorr::constraints::PublicKeyVar<JubJub, JubJubVar>;
type MsgVar = Vec<UInt8<ConstraintF>>;

pub const CITIZENSHIP_INDEX: usize = 0;
pub const AGE_INDEX: usize = 1;
pub const PROFESSION_INDEX: usize = 2;
pub const ORGAN_DONOR_INDEX: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Country {
    USA = 1,
    India = 91,
    UnitedKingdom = 44,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profession {
    Cryptographer = 0,
    Developer = 1,
    Professor = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrganDonor {
    Yes = 0,
    No = 1,
    Unknown = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attributes<const N: usize> {
    pub citizenship: Country,
    pub age: u8,
    pub profession: Profession,
    pub organ_donor: OrganDonor,
}

pub fn encode_attributes(attrs: &Attributes<4>) -> [Vec<u8>; 4] {
    let mut citizenship = vec![0u8; 1];
    citizenship[0] = match attrs.citizenship {
        Country::USA => 1,
        Country::India => 91,
        Country::UnitedKingdom => 44,
    };

    let mut age = vec![0u8; 1];
    age[0] = attrs.age;

    let mut profession = vec![0u8; 1];
    profession[0] = match attrs.profession {
        Profession::Cryptographer => 0,
        Profession::Developer => 1,
        Profession::Professor => 2,
    };

    let mut organ_donor = vec![0u8; 1];
    organ_donor[0] = match attrs.organ_donor {
        OrganDonor::Yes => 0,
        OrganDonor::No => 1,
        OrganDonor::Unknown => 2,
    };

    [citizenship, age, profession, organ_donor]
}

pub struct IssuerCircuit {
    pub nullifier_prf_instance: JZPRFInstance<H>, // PRF(issuer_sk, user_public_key)
    pub user_record: JZRecord<3, 4, ark_bls12_377::Fr>, // (sk, null, h_att)
    pub schnorr_parameters: <S as SignatureScheme>::Parameters,
    pub user_secret_key: <S as SignatureScheme>::SecretKey,
    pub user_public_key: <S as SignatureScheme>::PublicKey,
    pub issuer_secret_key: <S as SignatureScheme>::SecretKey,
    pub issuer_public_key: <S as SignatureScheme>::PublicKey,
    pub certification: <S as SignatureScheme>::Signature,
    pub attestation: <S as SignatureScheme>::Signature,
    pub statement_digest: ConstraintF,
    pub attributes_merkle_proof: JZVectorCommitmentOpeningProof<BigInteger256>,
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
    let msg_var = message.iter()
        .map(|b| UInt8::new_witness(cs.clone(), || Ok(b)).unwrap())
        .collect::<Vec<_>>();
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
        let user_record_var = JZRecordVar::<3, ConstraintF>::new_witness(
            cs.clone(),
            || Ok(self.user_record.borrow())
        ).unwrap();

        let user_record_com = self.user_record.commitment();

        record_commitment::sha256::constraints::generate_constraints(
            cs.clone(),
            &user_record_var
        ).unwrap();

        //--------------- Schnorr stuff ------------------

        // issuer's signature
        let (issuer_pk_var, issuer_signature_msg_var) = generate_schnorr_verification_constraints::<
            schnorr::Schnorr<JubJub>,
            SchnorrSignatureVerifyGadget<JubJub, JubJubVar>,
        >(
            cs.clone(),
            &self.schnorr_parameters,
            &self.certification,
            &self.issuer_public_key,
            &utils::serialize(&user_record_com)
        );
        let issuer_pk_var: SVar = issuer_pk_var.into();

        // user's signature
        let statement_digest_encoded = encode_statement(&self.statement_digest);
        let (user_pk_var, user_signature_msg_var) = generate_schnorr_verification_constraints::<
            schnorr::Schnorr<JubJub>,
            SchnorrSignatureVerifyGadget<JubJub, JubJubVar>,
        >(
            cs.clone(),
            &self.schnorr_parameters,
            &self.attestation,
            &self.user_public_key,
            &statement_digest_encoded
        );
        let user_pk_var: SVar = user_pk_var.into();

        //--------------- Merkle tree proof ------------------

        // the rng is not actually used, as there is no secret used in the params, so a test rng is fine
        let vc_params = JZVectorCommitmentParams::trusted_setup(&mut test_rng());

        let params_var = JZVectorCommitmentParamsVar::<ConstraintF>::
            new_constant(cs.clone(), &vc_params).unwrap();
        let proof_var = JZVectorCommitmentOpeningProofVar::<ConstraintF>::
            new_witness(cs.clone(),|| Ok(&self.attributes_merkle_proof)).unwrap();

        vector_commitment::bytes::sha256::constraints::generate_constraints(cs.clone(), &params_var, &proof_var);

        //--------------- Public Variable ------------------

        // make the issuer public key a public variable
        let public_var_issuer_public_key_x = ark_ed_on_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "issuer_public_key_x"), 
            || { Ok(self.issuer_public_key.x) },
        ).unwrap();
        issuer_pk_var.pub_key.x.enforce_equal(&public_var_issuer_public_key_x)?;

        let statement_digest_var = ark_ed_on_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "statement_digest"), 
            || { Ok(self.statement_digest) },
        ).unwrap();


        //--------------- Binding the PRF, PedCom, and two Schnorr signatures ------------------

        // only American vouches are allowed :P
        proof_var.leaf_var[0].enforce_equal(&UInt8::constant(Country::USA as u8))?;

        // message signed by the user
        let statement_digest_var_bytes = statement_digest_var.to_bytes_le().unwrap();
        for i in 0..user_signature_msg_var.len() {
            statement_digest_var_bytes[i].enforce_equal(&user_signature_msg_var[i])?;
        }

        // output of ped com is the input msg being signed
        let user_record_var_com_bytes = user_record_var
            .commitment
            .to_bytes_le()
            .unwrap();
        for i in 0..user_record_var_com_bytes.len() {
            user_record_var_com_bytes[i].enforce_equal(&issuer_signature_msg_var[i])?;
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
        // merkle root is at index 2 of the user record
        let root_byte_vars = proof_var.root_var.to_bytes_le().unwrap();
        for (i, byte_var) in user_record_var.fields[2].iter().enumerate() {
            byte_var.enforce_equal(&root_byte_vars[i])?;
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

fn hash_statement(statement: &str) -> [u8; 32] {
    let mut h = RO::evaluate(&(), &(statement).as_bytes()).unwrap();
    h[31] = 0u8;
    h
}

fn setup_witness() -> IssuerCircuit {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    // public parameters and CRS objects
    let prf_params = JZPRFParams::<H>::trusted_setup(&mut rng);

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

    let user: Attributes<4> = Attributes {
        citizenship: Country::USA,
        age: 30,
        profession: Profession::Cryptographer,
        organ_donor: OrganDonor::Yes,
    };
    let vc_params = JZVectorCommitmentParams::trusted_setup(&mut rng);
    let attributes = encode_attributes(&user).iter().map(|x| BigInteger256::from(x[0])).collect::<Vec<_>>();
    let attributes_merkle_tree = JZVectorDB::<BigInteger256>::new(&vc_params, &attributes);
    let attributes_merkle_root: Vec<u8> = attributes_merkle_tree.commitment();
    let attributes_merkle_proof = JZVectorCommitmentOpeningProof::<BigInteger256>
    {
        root: attributes_merkle_tree.commitment(),
        record: attributes_merkle_tree.get_record(CITIZENSHIP_INDEX).clone(),
        path: attributes_merkle_tree.proof(CITIZENSHIP_INDEX),
    };

    let fields: [Vec<u8>; 3] = [ user_pk_encoded, nullifier, attributes_merkle_root ];

    let user_record = JZRecord::<3, 4, ark_bls12_377::Fr>::new(&fields);

    let issuer_signed_message = utils::serialize(&user_record.commitment());
    let certification = S::sign(
        &schnorr_parameters,
        &issuer_secret_key,
        &issuer_signed_message,
        &mut rng
    ).unwrap();
    assert!(S::verify(&schnorr_parameters, &issuer_public_key, &issuer_signed_message, &certification).unwrap());

    let statement_digest_encoding = hash_statement("Hart is amazing");
    let statement_digest = ConstraintF::from(
        BigInt::<4>::from_bits_le(utils::bytes_to_bits(&statement_digest_encoding).as_slice())
    );
    let attestation = S::sign(
        &schnorr_parameters,
        &user_secret_key,
        &statement_digest_encoding,
        &mut rng
    ).unwrap();
    assert!(S::verify(&schnorr_parameters, &user_public_key, &statement_digest_encoding, &attestation).unwrap());

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
        statement_digest,
        attributes_merkle_proof
    }
}

#[allow(dead_code)]
fn circuit_setup() -> (ProvingKey<Bls12_377>, VerifyingKey<Bls12_377>) {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let circuit = setup_witness();

    let (pk, vk) = Groth16::<Bls12_377>::
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

    let public_input = [ circuit.issuer_public_key.x, circuit.statement_digest ];

    let now = std::time::Instant::now();
    let proof = Groth16::<Bls12_377>::prove(&pk, circuit, &mut rng).unwrap();
    let elapsed = now.elapsed();
    println!("Prover time: {:.2?}", elapsed);

    let valid_proof = Groth16::<Bls12_377>::verify(&vk, &public_input, &proof).unwrap();
    assert!(valid_proof);

}