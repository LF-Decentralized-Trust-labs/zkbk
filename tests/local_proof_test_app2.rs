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

use zkbk::record_commitment::kzg::{*, constraints::*};
use zkbk::record_commitment;

pub type ConstraintF = ark_bw6_761::Fr;

pub struct RecordComCircuit {
    pub record: JZRecord<4, 4, ark_bls12_377::Config>,
}

impl ConstraintSynthesizer<ConstraintF> for RecordComCircuit {
    //#[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<()> {
        let crs_var = JZKZGCommitmentParamsVar::<4, ark_bls12_377::Config>::new_constant(cs.clone(), self.record.crs.clone()).unwrap();
        let coin_var = JZRecordVar::<4, ark_bls12_377::Config, ark_bw6_761::Fr>::new_witness(cs.clone(), || Ok(self.record.borrow())).unwrap();

        let record = self.record.borrow();
        let computed_com = record.commitment().into_affine();

        let input_com_x = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_com_x"), 
            || { Ok(computed_com.x) },
        ).unwrap();

        let input_com_y = ark_bls12_377::constraints::FqVar::new_input(
            ark_relations::ns!(cs, "input_com_y"), 
            || { Ok(computed_com.y) },
        ).unwrap();

        record_commitment::kzg::constraints::generate_constraints(
            cs,
            &crs_var,
            &coin_var
        ).unwrap();

        // compute the affine var from the projective var
        let coin_com_affine = coin_var.commitment.to_affine().unwrap();

        // does the computed com match the input com?
        coin_com_affine.x.enforce_equal(&input_com_x)?;
        coin_com_affine.y.enforce_equal(&input_com_y)?;

        Ok(())
    }
}

fn setup_witness() -> RecordComCircuit {
    let seed = [0u8; 32];
    let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

    let crs = JZKZGCommitmentParams::<4, 4, ark_bls12_377::Config>::trusted_setup(&mut rng);

    let records: [Vec<u8>; 4] = 
    [
        vec![20u8, 30u8],
        vec![40u8, 50u8, 60u8, 70u8],
        vec![40u8, 50u8, 60u8, 70u8],
        vec![40u8, 50u8, 60u8, 70u8]
    ];
    
    RecordComCircuit {
        record: JZRecord::<4, 4, ark_bls12_377::Config>::new(&crs, &records),
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
    let com = circuit.record.commitment().into_affine();

    let public_input = [ com.x, com.y ];

    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();

    let valid_proof = Groth16::<BW6_761>::verify(&vk, &public_input, &proof).unwrap();
    assert!(valid_proof);

}