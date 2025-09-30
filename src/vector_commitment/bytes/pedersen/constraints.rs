// SPDX-License-Identifier: Apache-2.0

use ark_crypto_primitives::{
    to_uncompressed_bytes,
    crh::{CRHSchemeGadget, TwoToOneCRHSchemeGadget},
};
use crate::merkle_tree::constraints::{ConfigGadget, PathVar};

#[allow(unused)]
use ark_r1cs_std::prelude::*;
#[allow(unused)]
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use ark_serialize::CanonicalSerialize;
use ark_std::borrow::*;
use ark_relations::r1cs::*;
use ark_r1cs_std::{uint8::UInt8, alloc::AllocVar};
use ark_ff::PrimeField;

use super::*;

pub struct JZVectorCommitmentParamsVar<ConstraintF: PrimeField, P: Config, PG: ConfigGadget<P, ConstraintF>>
{
    pub leaf_crh_params_var: 
        <PG::LeafHash as CRHSchemeGadget<P::LeafHash, ConstraintF>>::ParametersVar,
    pub two_to_one_crh_params_var: 
        <PG::TwoToOneHash as TwoToOneCRHSchemeGadget<P::TwoToOneHash, ConstraintF>>::ParametersVar,
}

impl<P: Config, ConstraintF: PrimeField, PG: ConfigGadget<P, ConstraintF>>
    AllocVar<JZVectorCommitmentParams<P>, ConstraintF> for JZVectorCommitmentParamsVar<ConstraintF, P, PG> {
    fn new_variable<T: Borrow<JZVectorCommitmentParams<P>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T>,
        mode: AllocationMode
    ) -> Result<Self> {
        f().and_then(|val| {
            let cs = cs.into();
            
            let leaf_crh_params_var =
                <PG::LeafHash as CRHSchemeGadget<P::LeafHash, _>>::ParametersVar::
                new_variable(
                    cs.clone(),
                    || Ok(&val.borrow().leaf_crh_params),
                    mode,
                )?;

            let two_to_one_crh_params_var =
                <PG::TwoToOneHash as TwoToOneCRHSchemeGadget<P::TwoToOneHash, _>>::
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

pub struct JZVectorCommitmentOpeningProofVar<ConstraintF: PrimeField, P: Config, PG: ConfigGadget<P, ConstraintF>>
    where   P: Config,
            ConstraintF: PrimeField,
            PG: ConfigGadget<P, ConstraintF>,
            [u8]: std::borrow::Borrow<<P as Config>::Leaf>,
            PG: ConfigGadget<P, ConstraintF, Leaf = [UInt8<ConstraintF>]>,
            P: Config<Leaf = [u8]>
{
    pub path_var: PathVar<P, ConstraintF, PG>,
    pub root_var: <PG::TwoToOneHash as TwoToOneCRHSchemeGadget<P::TwoToOneHash, ConstraintF>>::OutputVar,
    pub leaf_var: Vec<UInt8<ConstraintF>>,
}

impl<L, ConstraintF, P, PG> AllocVar<JZVectorCommitmentOpeningProof<P, L>, ConstraintF> for 
    JZVectorCommitmentOpeningProofVar<ConstraintF, P, PG>
    where   L: CanonicalSerialize + Clone + Sized,
            P: Config,
            ConstraintF: PrimeField,
            PG: ConfigGadget<P, ConstraintF>,
            [u8]: std::borrow::Borrow<<P as Config>::Leaf>,
            P: Config<Leaf = [u8]>,
            PG: ConfigGadget<P, ConstraintF, Leaf = [UInt8<ConstraintF>]>
    {
    fn new_variable<T: Borrow<JZVectorCommitmentOpeningProof<P, L>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T>,
        mode: AllocationMode
    ) -> Result<Self> {
        f().and_then(|val| {
            let cs = cs.into();
            
            let opening_proof: &JZVectorCommitmentOpeningProof<P, L> = val.borrow();

            let root_var = <PG::TwoToOneHash as TwoToOneCRHSchemeGadget<P::TwoToOneHash, _>>::OutputVar
            ::new_variable(
                cs.clone(), 
                || Ok(opening_proof.root.clone()),
                mode
            )?;

            let record_bytes = to_uncompressed_bytes!(opening_proof.record).unwrap();
            let mut leaf_byte_vars = Vec::<UInt8<ConstraintF>>::new();
            for byte in record_bytes {
                leaf_byte_vars.push(UInt8::<ConstraintF>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }

            let path_var = PathVar::new_variable(
                cs.clone(),
                || Ok(&opening_proof.path),
                mode
            )?;

            Ok(
                JZVectorCommitmentOpeningProofVar::<ConstraintF, P, PG> {
                    path_var,
                    root_var,
                    leaf_var: leaf_byte_vars,
                }
            )
        })
    }
}


pub fn generate_constraints<ConstraintF: PrimeField, P: Config, PG: ConfigGadget<P, ConstraintF>>(
    _cs: ConstraintSystemRef<ConstraintF>,
    params: &JZVectorCommitmentParamsVar<ConstraintF, P, PG>,
    proof: &JZVectorCommitmentOpeningProofVar<ConstraintF, P, PG>
) 
    where   [u8]: std::borrow::Borrow<<P as Config>::Leaf>,
            PG: ConfigGadget<P, ConstraintF, Leaf = [UInt8<ConstraintF>]>,
            P: Config<Leaf = [u8]>
{

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

    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::BigInteger256;
    use rand::SeedableRng;

    type MTEdOnBls12_377 = config::ed_on_bls12_377::MerkleTreeParams;
    type MTVarEdOnBls12_377 = config::ed_on_bls12_377::MerkleTreeParamsVar;

    type MTEdOnBw6_761 = config::ed_on_bw6_761::MerkleTreeParams;
    type MTVarEdOnBw6_761 = config::ed_on_bw6_761::MerkleTreeParamsVar;

    fn generate_vc_params<P: crate::merkle_tree::Config>() -> JZVectorCommitmentParams<P> {
        let seed = [0u8; 32];
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);
        JZVectorCommitmentParams::<P>::trusted_setup(&mut rng)
    }

    #[test]
    fn test_vector_storage_bigint_constraint_gen() {
        
        let mut records: Vec<BigInteger256> = Vec::new();
        for x in 0..16u8 {
            records.push(BigInteger256::from(x));
        }

        let db = JZVectorDB::<MTEdOnBls12_377, BigInteger256>::new(
            generate_vc_params::<MTEdOnBls12_377>(), &records
        );
        let root = db.commitment();
        let path = db.proof(0);
        let proof = JZVectorCommitmentOpeningProof::<MTEdOnBls12_377, BigInteger256> {
            root,
            record: records[0].clone(),
            path: path.clone(),
        };

        let vc_params = generate_vc_params::<MTEdOnBls12_377>();
        assert!(verify_proof(&vc_params, &root, &records[0], &path));

        let cs = ConstraintSystem::<ark_bls12_377::Fr>::new_ref();

        let params_var = JZVectorCommitmentParamsVar::
        <ark_bls12_377::Fr, MTEdOnBls12_377, MTVarEdOnBls12_377>
        ::new_constant(
            cs.clone(),
            &vc_params
        ).unwrap();

        let proof_var = JZVectorCommitmentOpeningProofVar::
        <ark_bls12_377::Fr, MTEdOnBls12_377, MTVarEdOnBls12_377>
        ::new_witness(
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
        let mut records = Vec::new();
        for x in 0..16u8 {
            let x_bi = BigInteger256::from(x);
            let g_pow_x_i = ark_bls12_377::G1Affine::generator()
                .mul_bigint(x_bi)
                .into_affine();
            records.push(g_pow_x_i);
        }

        let idx = 5;
        let db = JZVectorDB::<MTEdOnBw6_761, ark_bls12_377::G1Affine>::new(
            generate_vc_params::<MTEdOnBw6_761>(), &records
        );
        let root = db.commitment();
        let path = db.proof(idx);
        let proof = JZVectorCommitmentOpeningProof::<MTEdOnBw6_761, ark_bls12_377::G1Affine> {
            root,
            record: records[idx].clone(),
            path: path.clone(),
        };

        let vc_params = generate_vc_params::<MTEdOnBw6_761>();

        assert!(verify_proof(&vc_params, &root, &records[idx], &path));

        let cs = ConstraintSystem::<ark_bw6_761::Fr>::new_ref();

        let params_var = JZVectorCommitmentParamsVar::
        <ark_bw6_761::Fr, MTEdOnBw6_761, MTVarEdOnBw6_761>
        ::new_constant(
            cs.clone(),
            &vc_params
        ).unwrap();

        let proof_var = JZVectorCommitmentOpeningProofVar::
        <ark_bw6_761::Fr, MTEdOnBw6_761, MTVarEdOnBw6_761>
        ::new_witness(
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