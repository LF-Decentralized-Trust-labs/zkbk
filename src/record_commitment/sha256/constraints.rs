// SPDX-License-Identifier: Apache-2.0

use ark_crypto_primitives::crh::CRHSchemeGadget;
use ark_ff::*;
use ark_relations::r1cs::*;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::{uint8::UInt8, prelude::*};
use ark_std::{borrow::*, *};
use ark_crypto_primitives::crh::sha256::{*, constraints::*};

use super::JZRecord;

pub struct JZRecordVar<const N: usize, ConstraintF>
    where ConstraintF: PrimeField
{
    pub fields: [Vec<UInt8<ConstraintF>>; N],
    pub commitment: DigestVar<ConstraintF>,
}

impl<const N: usize, const M: usize, RecordF: PrimeField + std::convert::From<BigInt<M>>, ConstraintF: PrimeField>
AllocVar<JZRecord<N, M, RecordF>, ConstraintF> for JZRecordVar<N, ConstraintF> {
    fn new_variable<T: Borrow<JZRecord<N, M, RecordF>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T>,
        mode: AllocationMode
    ) -> Result<Self> {
        f().and_then(|val| {
            let cs = cs.into();
            let fields: &[Vec<u8>; N] = &val.borrow().fields;

            // we will collect all variables here
            let mut byte_vars: Vec<Vec<UInt8<ConstraintF>>> = vec![];
            for i in 0..N {
                let mut field_byte_vars = vec![];
                // allocate a byte var for each byte within each of the N fields
                for byte in fields[i].as_slice() {
                    field_byte_vars.push(UInt8::<ConstraintF>::new_variable(
                        cs.clone(), || Ok(byte), mode
                    )?);
                }
                byte_vars.push(field_byte_vars);
            }

            let sha256_com: [u8; 32] = val.borrow().commitment();
            let sha256_digest = DigestVar::new_variable(
                cs.clone(),
                || Ok(sha256_com.to_vec()),
                mode
            )?;

            Ok( JZRecordVar { fields: byte_vars.try_into().unwrap(), commitment: sha256_digest } )
        })
    }
}

pub fn generate_constraints<const N: usize, ConstraintF: PrimeField>(
    _cs: ConstraintSystemRef<ConstraintF>,
    record: &JZRecordVar<N, ConstraintF>
) -> Result<()> {

    let all_byte_vars: Vec<UInt8<ConstraintF>> = record.fields
        .iter()
        .flat_map(|v| v.iter().cloned())
        .collect();

    let computed_output = 
        <Sha256Gadget<ConstraintF> as CRHSchemeGadget<Sha256, ConstraintF>>::
            evaluate(&UnitVar::default(), &all_byte_vars)?;

    computed_output.enforce_equal(&record.commitment)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use rand::RngCore;

    #[test]
    fn test_sha256_com() {
        let mut rng = test_rng();

        let mut entropy = [0u8; 31];
        rng.fill_bytes(&mut entropy);

        let records: [Vec<u8>; 4] = [vec![20u8; 31], vec![244u8; 31], vec![244u8; 31], vec![244u8; 31]];

        let coin = JZRecord::<4, 4, ark_bls12_377::Fr>::new(&records);

        let cs = ConstraintSystem::<ark_bw6_761::Fr>::new_ref();
        let coin_var = JZRecordVar::<4, ark_bw6_761::Fr>::new_witness(cs.clone(), || Ok(coin)).unwrap();

        generate_constraints(cs.clone(), &coin_var).unwrap();
        assert!(cs.is_satisfied().unwrap(), "constraints not satisfied");
    }
}