// SPDX-License-Identifier: Apache-2.0

use ark_crypto_primitives::crh::CRHSchemeGadget;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_std::borrow::*;
use ark_relations::r1cs::*;
use ark_r1cs_std::{uint8::UInt8, alloc::AllocVar};

use super::*;

pub struct JZPRFParamsVar<H: CRHScheme, HG: CRHSchemeGadget<H, ConstraintF>, ConstraintF: PrimeField> {
    pub crh_params_var: <HG as CRHSchemeGadget<H, ConstraintF>>::ParametersVar,
}

impl<H: CRHScheme, HG: CRHSchemeGadget<H, ConstraintF>, ConstraintF: PrimeField>
AllocVar<JZPRFParams<H>, ConstraintF> for JZPRFParamsVar<H, HG, ConstraintF> {
    fn new_variable<T: Borrow<JZPRFParams<H>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T>,
        mode: AllocationMode
    ) -> Result<Self> {
        f().and_then(|val| {
            let cs = cs.into();
            
            let crh_params_var =
                <HG as CRHSchemeGadget<H, ConstraintF>>::ParametersVar::
                new_variable(
                    cs.clone(),
                    || Ok(&val.borrow().crh_params),
                    mode,
                )?;

            Ok( JZPRFParamsVar { crh_params_var } )
        })
    }
}

pub struct JZPRFInstanceVar<ConstraintF: PrimeField> {
    pub input_var: Vec<UInt8<ConstraintF>>,
    pub key_var: Vec<UInt8<ConstraintF>>,
    pub output_var: Vec<UInt8<ConstraintF>>,
}

impl<H: CRHScheme, ConstraintF: PrimeField> AllocVar<JZPRFInstance<H>, ConstraintF> for JZPRFInstanceVar<ConstraintF> 
    where   Vec<u8>: std::borrow::Borrow<<H as ark_crypto_primitives::crh::CRHScheme>::Input>,
{
    fn new_variable<T: Borrow<JZPRFInstance<H>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T>,
        mode: AllocationMode
    ) -> Result<Self> {
        f().and_then(|val| {
            let cs = cs.into();
            
            let prf_instance: &JZPRFInstance<H> = val.borrow();

            let mut input_byte_vars = Vec::<UInt8<ConstraintF>>::new();
            for byte in prf_instance.input.iter() {
                input_byte_vars.push(UInt8::<ConstraintF>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }

            let mut key_byte_vars = Vec::<UInt8<ConstraintF>>::new();
            for byte in prf_instance.key.iter() {
                key_byte_vars.push(UInt8::<ConstraintF>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }

            let mut output_byte_vars = Vec::<UInt8<ConstraintF>>::new();
            let prf_output = prf_instance.evaluate();

            for byte in prf_output.iter() {
                output_byte_vars.push(UInt8::<ConstraintF>::new_variable(
                    cs.clone(),
                    || Ok(byte),
                    mode,
                )?);
            }

            Ok(
                JZPRFInstanceVar {
                    input_var: input_byte_vars,
                    key_var: key_byte_vars,
                    output_var: output_byte_vars,
                }
            )
        })
    }
}


pub fn generate_constraints<
    H: CRHScheme,
    HG: CRHSchemeGadget<H, ConstraintF, InputVar = [UInt8<ConstraintF>]>,
    ConstraintF: PrimeField
>
(
    _cs: ConstraintSystemRef<ConstraintF>,
    params: &JZPRFParamsVar<H, HG, ConstraintF>,
    prf_instance: &JZPRFInstanceVar<ConstraintF>,
)
{
    let mut input = vec![];
    input.extend_from_slice(&prf_instance.input_var);
    input.extend_from_slice(&prf_instance.key_var);

    let crh_output_var = HG::evaluate(
        &params.crh_params_var,
        &input
    ).unwrap();

    let len = prf_instance.output_var.len();
    let crh_output_var_bytes = crh_output_var.to_bytes_le().unwrap();

    for (i, byte_var) in crh_output_var_bytes[0..len].iter().enumerate() {
        byte_var.enforce_equal(&prf_instance.output_var[i]).unwrap();
    }
}
