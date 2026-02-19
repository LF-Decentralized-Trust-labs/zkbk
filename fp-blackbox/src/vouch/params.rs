use crate::gro15::{flipped, standard};
use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use ark_poly::univariate::DensePolynomial;
use ark_std::{rand::Rng, One, UniformRand};

#[derive(Clone, Debug)]
pub struct PublicParams<E: Pairing> {
    pub gro15_params: standard::Params<E>,
    pub flipped_params: flipped::Params<E>,
    // CRS for KZG: g^{tau^i} and h^{tau^i}
    pub crs_g1: Vec<E::G1>,
    pub crs_g2: Vec<E::G2>,
}

impl<E: Pairing> PublicParams<E> {
    pub fn new<R: Rng>(max_degree: usize, rng: &mut R) -> Self {
        let gro15_params = standard::Params::new(rng);
        let flipped_params = flipped::Params::new(rng);

        let tau = E::ScalarField::rand(rng);

        let mut crs_g1 = Vec::with_capacity(max_degree + 1);
        let mut crs_g2 = Vec::with_capacity(max_degree + 1);

        let mut cur_tau = E::ScalarField::one();
        for _ in 0..=max_degree {
            crs_g1.push(gro15_params.g * cur_tau);
            crs_g2.push(gro15_params.h * cur_tau);
            cur_tau *= tau;
        }

        PublicParams {
            gro15_params,
            flipped_params,
            crs_g1,
            crs_g2,
        }
    }

    pub fn commit_g1(&self, poly: &DensePolynomial<E::ScalarField>) -> E::G1 {
        let mut com = E::G1::zero();
        for (i, coeff) in poly.coeffs.iter().enumerate() {
            if i < self.crs_g1.len() {
                com += self.crs_g1[i] * coeff;
            } else {
                panic!("CRS too small for polynomial degree");
            }
        }
        com
    }

    pub fn commit_g2(&self, poly: &DensePolynomial<E::ScalarField>) -> E::G2 {
        let mut com = E::G2::zero();
        for (i, coeff) in poly.coeffs.iter().enumerate() {
            if i < self.crs_g2.len() {
                com += self.crs_g2[i] * coeff;
            } else {
                panic!("CRS too small for polynomial degree");
            }
        }
        com
    }
}
