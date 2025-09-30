// SPDX-License-Identifier: Apache-2.0

use ark_ff::*;
use ark_std::{borrow::*, *};
use std::ops::AddAssign;
use ark_relations::r1cs::*;
use ark_r1cs_std::{uint8::UInt8, prelude::*, alloc::AllocVar};
use ark_r1cs_std::groups::curves::short_weierstrass::bls12::*;
use ark_ec::{models::bls12::*, bls12::Bls12Config, CurveConfig};

use super::{JZRecord, JZPedCommitmentParams};

pub struct JZPedCommitmentParamsVar<const N: usize, C: Bls12Config> {
    pub crs: Vec<G1Var<C>>,
}

pub struct JZRecordVar<const N: usize, C, ConstraintF> 
    where   C: Bls12Config<Fp = ConstraintF>,
            ConstraintF: PrimeField,
{
    pub fields: [Vec<UInt8<ConstraintF>>; N],
    pub commitment: G1Var<C>,
}

impl<const N: usize, const M: usize, C: Bls12Config, ConstraintF: PrimeField>
    AllocVar<JZPedCommitmentParams<N, M, C>, ConstraintF> for JZPedCommitmentParamsVar<N, C>
    where   C: Bls12Config<Fp = ConstraintF>,
            <<C as Bls12Config>::G1Config as CurveConfig>::ScalarField: std::convert::From<BigInt<M>>,
            ConstraintF: PrimeField,
{
    fn new_variable<T: Borrow<JZPedCommitmentParams<N, M, C>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T>,
        mode: AllocationMode
    ) -> Result<Self> {
        f().and_then(|val| {
            let cs = cs.into();
            let crs: &Vec<G1Projective<C>> = &val.borrow().crs_coefficients;
            let mut crs_vars: Vec<G1Var<C>> = vec![];
            for i in 0..N {
                let crs_i = G1Var::<C>::new_variable(
                    cs.clone(),
                    || Ok(crs[i]),
                    mode)?;

                crs_vars.push(crs_i);
            }

            Ok(JZPedCommitmentParamsVar { crs: crs_vars })
        })
    }
}

impl<const N: usize, const M: usize, C, ConstraintF> AllocVar<JZRecord<N, M, C>, ConstraintF> for JZRecordVar<N, C, ConstraintF>
    where   C: Bls12Config<Fp = ConstraintF>,
            ConstraintF: PrimeField,
            <<C as Bls12Config>::G1Config as CurveConfig>::ScalarField: std::convert::From<BigInt<M>>
{
    fn new_variable<T: Borrow<JZRecord<N, M, C>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T>,
        mode: AllocationMode
    ) -> Result<Self> {
        f().and_then(|val| {
            let cs = cs.into();
            let fields: &[Vec<u8>; N] = &val.borrow().fields;
            let mut constraint_fields: Vec<Vec<UInt8<ConstraintF>>> = vec![];
            for i in 0..N {
                let mut field_byte_vars = Vec::<UInt8<ConstraintF>>::new();
                let field_bytes: &Vec<u8> = &fields[i];

                for byte in field_bytes {
                    field_byte_vars.push(UInt8::<ConstraintF>::new_variable(
                        cs.clone(),
                        || Ok(byte),
                        mode,
                    )?);
                }

                constraint_fields.push(field_byte_vars);
            }

            let computed_ped_com: G1Projective<C> = val.borrow().commitment();

            let ped_com_var = G1Var::<C>::new_variable(
                cs.clone(),
                || Ok(computed_ped_com),
                mode
            )?;

            Ok(
                JZRecordVar {
                    fields: constraint_fields.try_into().unwrap(),
                    commitment: ped_com_var,
                }
            )
        })
    }
}

pub fn generate_constraints<const N: usize, C, ConstraintF>(
    cs: ConstraintSystemRef<ConstraintF>,
    params: &JZPedCommitmentParamsVar<N, C>,
    record: &JZRecordVar<N, C, ConstraintF>
) -> Result<()> 
where   C: Bls12Config<Fp = ConstraintF>,
        ConstraintF: PrimeField,
{

    let mut aggregate_var = G1Var::<C>::new_witness(
        ark_relations::ns!(cs, "aggregate_pk"), 
        || Ok(G1Projective::<C>::zero())
    )?;

    for i in 0..N {        
        let crs_i: &G1Var<C> = &params.crs[i];
        let elem_i: &Vec<UInt8<ConstraintF>> = &record.fields[i];

        let crs_i_pow_elem_i: G1Var<C> = crs_i.scalar_mul_le(
            elem_i.to_bits_le()?.iter())?;

        aggregate_var.add_assign(crs_i_pow_elem_i);
    }

    record.commitment.enforce_equal(&aggregate_var)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use rand::RngCore;

    #[test]
    fn test_kzg_com() {
        let mut rng = test_rng();
        let crs = JZPedCommitmentParams::<4, 4, ark_bls12_377::Config>::trusted_setup(&mut rng);

        let mut entropy = [0u8; 24];
        rng.fill_bytes(&mut entropy);

        let records: [Vec<u8>; 4] = 
            [
                vec![20u8, 30u8],
                vec![
                    255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8,
                    254u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8,
                    253u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8,
                ],
                vec![
                    255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8,
                    255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8,
                    255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8, 255u8,
                ],
                vec![40u8, 50u8, 60u8, 70u8]
            ];

        let coin = JZRecord::<4, 4, ark_bls12_377::Config>::new(&crs, &records);

        let cs = ConstraintSystem::<ark_bw6_761::Fr>::new_ref();

        let crs_var = JZPedCommitmentParamsVar::<4, ark_bls12_377::Config>::new_constant(cs.clone(), crs).unwrap();
        let coin_var = JZRecordVar::<4, ark_bls12_377::Config, ark_bls12_377::Fq>::new_witness(cs.clone(), || Ok(coin)).unwrap();

        generate_constraints(cs.clone(), &crs_var, &coin_var).unwrap();
        assert!(cs.is_satisfied().unwrap(), "constraints not satisfied");
    }
}