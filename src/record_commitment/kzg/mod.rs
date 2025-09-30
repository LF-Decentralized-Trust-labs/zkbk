// SPDX-License-Identifier: Apache-2.0

pub mod constraints;

use ark_ec::*;
use ark_std::{*, rand::Rng};
use ark_std::borrow::*;
use ark_std::convert::*;
use ark_ff::*;
use ark_poly::Polynomial;
use ark_ec::models::bls12::*;

use crate::utils;

//#[derive(Clone)]
#[derive(Derivative)]
#[derivative(Clone(bound = "C: Bls12Config"))]
pub struct JZKZGCommitmentParams<const N: usize, const M: usize, C: Bls12Config> 
    where <<C as Bls12Config>::G1Config as CurveConfig>::ScalarField: std::convert::From<BigInt<M>>
{
    /// KZG CRS in the coefficient basis
    pub crs_coefficient_g1: Vec<G1Projective<C>>,
    /// KZG CRS in the coefficient basis
    pub crs_coefficient_g2: Vec<G2Projective<C>>,
    /// KZG CRS in the Lagrange basis
    pub crs_lagrange: Vec<G1Projective<C>>,
}

type ScalarField<P> = <<P as Bls12Config>::G1Config as CurveConfig>::ScalarField;

impl<const N: usize, const M: usize, C: Bls12Config> JZKZGCommitmentParams<N, M, C>
    where <<C as Bls12Config>::G1Config as CurveConfig>::ScalarField: std::convert::From<BigInt<M>>,
{

    pub fn trusted_setup<R: Rng>(_rng: &mut R) -> Self {  
        let tau: ScalarField<C> = ScalarField::<C>::from(BigInt::<M>::from(42 as u32));

        let g = G1Projective::<C>::generator();
        let h = G2Projective::<C>::generator();

        let crs_coefficient_g1 = (0..4*N)
            .map(|i| g.mul_bigint(
                tau.pow(
                    &[i as u64]
                ).into_bigint()
            ))
            .collect();

        let crs_coefficient_g2 = (0..4*N)
            .map(|i| h.mul_bigint(
                tau.pow(
                    &[i as u64]
                ).into_bigint()
            ))
            .collect();

        let crs_lagrange = (0..N)
            .map(|i| g.mul_bigint(
                utils::lagrange_poly(N, i)
                .evaluate(&tau)
                .into_bigint()
                ))
            .collect();

        JZKZGCommitmentParams { crs_coefficient_g1, crs_coefficient_g2, crs_lagrange }
    }
}

/// JZRecord<N,M,C> where N is the number of fields and M is the size of each field (in u64s)
#[derive(Derivative)]
#[derivative(Clone(bound = "C: Bls12Config"))]
pub struct JZRecord<const N: usize, const M: usize, C: Bls12Config>
    where <<C as Bls12Config>::G1Config as CurveConfig>::ScalarField: std::convert::From<BigInt<M>>
{
    pub crs: JZKZGCommitmentParams<N, M, C>,
    pub fields: [Vec<u8>; N], //Nth field is the entropy
}

impl<const N: usize, const M: usize, C: Bls12Config> JZRecord<N, M, C>
    where <<C as Bls12Config>::G1Config as CurveConfig>::ScalarField: std::convert::From<BigInt<M>>
{
    pub fn new(
        crs: &JZKZGCommitmentParams<N, M, C>,
        fields: &[Vec<u8>; N],
    ) -> Self {
        JZRecord {
            crs: (*crs).clone(),
            fields: fields.to_owned(),
        }
    }

    pub fn commitment(&self) -> G1Projective<C> {
        let mut acc = G1Projective::<C>::zero();
        for (i, field) in self.fields.iter().enumerate() {
            if i < N {
                let crs_elem = self.crs.crs_lagrange[i];
                let exp = BigInt::<M>::from_bits_le(
                    utils::bytes_to_bits(&field).as_slice()
                );
                
                acc += crs_elem.clone().mul_bigint(exp);
            }
        }
        acc
    }

    pub fn fields(&self) -> [ScalarField<C>; N] {
        let mut fields = [ScalarField::<C>::zero(); N];
        for (i, field) in self.fields.iter().enumerate() {
            fields[i] = ScalarField::<C>::from(
                BigInt::<M>::from_bits_le(
                    utils::bytes_to_bits(&field).as_slice()
                )
            );
        }
        fields
    }
}
