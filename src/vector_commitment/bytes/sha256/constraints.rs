// SPDX-License-Identifier: Apache-2.0

use ark_crypto_primitives::crh::{
        constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
        sha256::constraints::Sha256Gadget,
};
use ark_ff::PrimeField;
use crate::merkle_tree::constraints::{PathVar, BytesVarDigestConverter, ConfigGadget};
#[allow(unused)]
use ark_r1cs_std::prelude::*;
#[allow(unused)]
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use ark_serialize::CanonicalSerialize;
use ark_std::borrow::*;
use ark_relations::r1cs::*;
use ark_r1cs_std::{uint8::UInt8, alloc::AllocVar};

use super::*;
use super::common::*;

type LeafHG<ConstraintF> = Sha256Gadget<ConstraintF>;
type CompressHG<ConstraintF> = Sha256Gadget<ConstraintF>;

type LeafVar<ConstraintF> = [UInt8<ConstraintF>];

#[derive(Debug)]
pub struct Sha256MerkleTreeParamsVar<ConstraintF> {
    _field: core::marker::PhantomData<ConstraintF>,
}

impl<ConstraintF: PrimeField> ConfigGadget<Sha256MerkleTreeParams, ConstraintF> for Sha256MerkleTreeParamsVar<ConstraintF> {
    type Leaf = LeafVar<ConstraintF>;
    type LeafDigest = <LeafHG<ConstraintF> as CRHSchemeGadget<LeafH, ConstraintF>>::OutputVar;
    type LeafInnerConverter = BytesVarDigestConverter<Self::LeafDigest, ConstraintF>;
    type InnerDigest = <CompressHG<ConstraintF> as TwoToOneCRHSchemeGadget<CompressH, ConstraintF>>::OutputVar;
    type LeafHash = LeafHG<ConstraintF>;
    type TwoToOneHash = CompressHG<ConstraintF>;
}

pub struct JZVectorCommitmentParamsVar<ConstraintF: PrimeField> {
    pub leaf_crh_params_var: 
        <LeafHG<ConstraintF> as CRHSchemeGadget<LeafH, ConstraintF>>::ParametersVar,
    pub two_to_one_crh_params_var: 
        <CompressHG<ConstraintF> as TwoToOneCRHSchemeGadget<CompressH, ConstraintF>>::ParametersVar,
}

impl<ConstraintF: PrimeField> AllocVar<JZVectorCommitmentParams, ConstraintF> for JZVectorCommitmentParamsVar<ConstraintF> {
    fn new_variable<T: Borrow<JZVectorCommitmentParams>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T>,
        mode: AllocationMode
    ) -> Result<Self> {
        f().and_then(|val| {
            let cs = cs.into();
            
            //let crh_params = ();
            let leaf_crh_params_var =
                <LeafHG<ConstraintF> as CRHSchemeGadget<LeafH, ConstraintF>>::ParametersVar::
                new_variable(
                    cs.clone(),
                    || Ok(&val.borrow().leaf_crh_params),
                    mode,
                )?;

            let two_to_one_crh_params_var =
                <CompressHG<ConstraintF> as TwoToOneCRHSchemeGadget<CompressH, ConstraintF>>::
                ParametersVar::new_variable(
                    cs.clone(),
                    || Ok(&val.borrow().two_to_one_params),
                    mode,
                )?;

            Ok(
                JZVectorCommitmentParamsVar {
                    leaf_crh_params_var,
                    two_to_one_crh_params_var
                }
            )
        })
    }
}

pub struct JZVectorCommitmentOpeningProofVar<ConstraintF: PrimeField> {
    pub path_var: PathVar<Sha256MerkleTreeParams, ConstraintF, Sha256MerkleTreeParamsVar<ConstraintF>>,
    pub leaf_var: Vec<UInt8<ConstraintF>>,
    pub root_var: <CompressHG<ConstraintF> as TwoToOneCRHSchemeGadget<CompressH, ConstraintF>>::OutputVar,
}

impl<L: CanonicalSerialize + Clone, ConstraintF: PrimeField> 
    AllocVar<JZVectorCommitmentOpeningProof<L>, ConstraintF> for JZVectorCommitmentOpeningProofVar<ConstraintF> {
    fn new_variable<T: Borrow<JZVectorCommitmentOpeningProof<L>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T>,
        mode: AllocationMode
    ) -> Result<Self> {
        f().and_then(|val| {
            let cs = cs.into();
            
            let opening_proof: &JZVectorCommitmentOpeningProof<L> = val.borrow();

            let root_var = <CompressHG<ConstraintF> as TwoToOneCRHSchemeGadget<CompressH, ConstraintF>>::
            OutputVar::new_variable(
                cs.clone(), 
                || Ok(opening_proof.root.clone()),
                mode
            )?;

            let mut record_bytes = Vec::new();
            opening_proof.record
                .borrow()
                .serialize_uncompressed(&mut record_bytes)
                .unwrap();

            let mut leaf_byte_vars = Vec::<UInt8<ConstraintF>>::new();
            for byte in record_bytes {
                leaf_byte_vars.push(UInt8::<ConstraintF>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }

            let path_var: PathVar<Sha256MerkleTreeParams, ConstraintF, Sha256MerkleTreeParamsVar<ConstraintF>> = PathVar::new_variable(
                cs.clone(),
                || Ok(&opening_proof.path),
                mode
            )?;

            Ok(
                JZVectorCommitmentOpeningProofVar {
                    path_var,
                    leaf_var: leaf_byte_vars,
                    root_var,
                }
            )
        })
    }
}


pub fn generate_constraints<ConstraintF: PrimeField>(
    _cs: ConstraintSystemRef<ConstraintF>,
    params: &JZVectorCommitmentParamsVar<ConstraintF>,
    proof: &JZVectorCommitmentOpeningProofVar<ConstraintF>,
) {

    let path_validity = proof.path_var.verify_membership(
        &params.leaf_crh_params_var,
        &params.two_to_one_crh_params_var,
        &proof.root_var,
        &proof.leaf_var,
    ).unwrap();

    path_validity.enforce_equal(&Boolean::TRUE).unwrap();

}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_std::test_rng;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::BigInteger256;
    use ark_bls12_377::*;
    use ark_bw6_761::Fr as ConstraintF;

    #[test]
    fn test_vector_storage_bigint_constraint_gen() {
        let mut rng = test_rng();
        let vc_params = JZVectorCommitmentParams::trusted_setup(&mut rng);

        let mut records = Vec::new();
        for x in 0..16u8 {
            records.push(BigInteger256::from(x));
        }

        let db = JZVectorDB::<BigInteger256>::new(&vc_params, &records);
        let root = db.commitment();
        let path = db.proof(0);
        let proof = JZVectorCommitmentOpeningProof {
            root: root.clone(),
            record: records[0].clone(),
            path: path.clone(),
        };

        assert!(verify_vc_opening_proof(&vc_params, &root, &records[0], &path));

        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let params_var = JZVectorCommitmentParamsVar::new_constant(
            cs.clone(),
            &vc_params
        ).unwrap();

        let proof_var = JZVectorCommitmentOpeningProofVar::new_witness(
            cs.clone(),
            || Ok(&proof)
        ).unwrap();

        generate_constraints(
            cs.clone(),
            &params_var,
            &proof_var,
        );
        assert!(cs.is_satisfied().unwrap(), "constraints not satisfied");
    }

    #[test]
    fn test_vector_storage_g1_constraint_gen() {
        let mut rng = test_rng();
        let vc_params = JZVectorCommitmentParams::trusted_setup(&mut rng);

        let mut records = Vec::new();
        for x in 0..16u8 {
            let x_bi = BigInteger256::from(x);
            let g_pow_x_i = G1Affine::generator()
                .mul_bigint(x_bi)
                .into_affine();
            records.push(g_pow_x_i);
        }

        let idx = 5;
        let db = JZVectorDB::<G1Affine>::new(&vc_params, &records);
        let root = db.commitment();
        let path = db.proof(idx);
        let proof = JZVectorCommitmentOpeningProof {
            root: root.clone(),
            record: records[idx].clone(),
            path: path.clone(),
        };

        assert!(verify_vc_opening_proof(&vc_params, &root, &records[idx], &path));

        let cs = ConstraintSystem::<ConstraintF>::new_ref();

        let params_var = JZVectorCommitmentParamsVar::new_constant(
            cs.clone(),
            &vc_params
        ).unwrap();

        let proof_var = JZVectorCommitmentOpeningProofVar::new_witness(
            cs.clone(),
            || Ok(&proof)
        ).unwrap();
        
        generate_constraints(
            cs.clone(),
            &params_var,
            &proof_var,
        );
        assert!(cs.is_satisfied().unwrap(), "constraints not satisfied");
    }
}