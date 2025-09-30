use rand_chacha::rand_core::SeedableRng;
use ark_ec::{*};
use ark_ff::{*};
use ark_bw6_761::{*};
use ark_r1cs_std::prelude::*;
use ark_std::*;
use ark_relations::r1cs::*;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_snark::SNARK;

use zkbk::vector_commitment::bytes::pedersen::{*, constraints::*};
use zkbk::vector_commitment;

pub type ConstraintF = ark_bw6_761::Fr;
type MT = config::ed_on_bw6_761::MerkleTreeParams;
type MTVar = config::ed_on_bw6_761::MerkleTreeParamsVar;

pub struct PokOfRecordCircuit {
    pub db: JZVectorDB<MT, ark_bls12_377::G1Affine>,
    pub index: usize,
}

impl ConstraintSynthesizer<ConstraintF> for PokOfRecordCircuit {
    //#[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<()> {

        let proof = JZVectorCommitmentOpeningProof::<MT, ark_bls12_377::G1Affine> {
            root: self.db.commitment(),
            record: self.db.get_record(self.index).clone(),
            path: self.db.proof(self.index),
        };
        
        let params_var = JZVectorCommitmentParamsVar
        ::<ConstraintF, MT, MTVar>
        ::new_constant(
            cs.clone(),
            &self.db.vc_params
        ).unwrap();

        let proof_var = JZVectorCommitmentOpeningProofVar
        ::<ConstraintF, MT, MTVar>
        ::new_witness(
            cs.clone(),
            || Ok(&proof)
        ).unwrap();

        let root_com_x = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_com_x"), 
            || { Ok(proof.root.x) },
        ).unwrap();

        let root_com_y = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_com_y"), 
            || { Ok(proof.root.y) },
        ).unwrap();

        proof_var.root_var.x.enforce_equal(&root_com_x)?;
        proof_var.root_var.y.enforce_equal(&root_com_y)?;

        vector_commitment::bytes::pedersen::constraints::generate_constraints(
            cs, &params_var, &proof_var
        );
        Ok(())
    }
}

fn setup_witness() -> PokOfRecordCircuit {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let vc_params = JZVectorCommitmentParams::trusted_setup(&mut rng);

    let mut records = Vec::new();
    for x in 0..16u8 {
        let x_bi = BigInteger256::from(x);
        let g_pow_x_i = ark_bls12_377::G1Affine::generator()
            .mul_bigint(x_bi)
            .into_affine();
        records.push(g_pow_x_i);
    }

    let db = JZVectorDB::<MT, ark_bls12_377::G1Affine>::new(vc_params, &records);
    
    PokOfRecordCircuit {
        db: db,
        index: 0,
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
fn pok_of_record() {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let (pk, vk) = circuit_setup();

    let circuit = setup_witness();
    let input_root = circuit.db.commitment();

    let public_input = [ input_root.x, input_root.y ];

    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();

    let valid_proof = Groth16::<BW6_761>::verify(&vk, &public_input, &proof).unwrap();
    assert!(valid_proof);

}