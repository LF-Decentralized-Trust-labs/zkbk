// SPDX-License-Identifier: Apache-2.0

pub mod constraints;

use ark_crypto_primitives::crh::{CRHScheme, sha256::*};
use ark_std::{*, borrow::*};
use ark_ff::*;
use ark_std::marker::PhantomData;

use crate::utils;

fn hash_of_fields(fields: &[Vec<u8>]) -> [u8; 32] {
    let mut concatenated = Vec::new();
    for field in fields.iter() {
        concatenated.extend_from_slice(field);
    }

    let h = Sha256::evaluate(&(), concatenated).unwrap();
    h.try_into().expect("expected sha256 output to be 32 bytes")
}

#[derive(Clone)]
pub struct JZRecord<const N: usize, const M: usize, RecordF: PrimeField + std::convert::From<BigInt<M>>> {
    pub fields: [Vec<u8>; N], //Nth field is the entropy
    pub _phantom: PhantomData<RecordF>
}

impl<const N: usize, const M: usize, RecordF: PrimeField + std::convert::From<BigInt<M>>> JZRecord<N, M, RecordF> {
    pub fn new(fields: &[Vec<u8>; N]) -> Self {
        JZRecord::<N, M, RecordF> {
            fields: fields.to_owned(),
            _phantom: PhantomData
        }
    }

    pub fn commitment(&self) -> [u8; 32] {
        hash_of_fields(&self.fields)
    }

    pub fn fields(&self) -> [RecordF; N] {
        self.fields
            .iter()
            .map(|field| utils::bytes_to_field::<RecordF, M>(field))
            .collect::<Vec<RecordF>>()
            .try_into()
            .unwrap()
    }
}
