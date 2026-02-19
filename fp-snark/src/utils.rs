use ark_ff::*;
use ark_std::*;
use ark_ff::{
    PrimeField,
    BigInt,
};
use ark_poly::{
    Polynomial,
    univariate::DensePolynomial, 
    EvaluationDomain, 
    Radix2EvaluationDomain,
    Evaluations
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub fn serialize<T: CanonicalSerialize>(
    t: &T
) -> Vec<u8> {
    let mut buf = Vec::new();
    // unwrap() should be safe because we serialize into a variable-size vector.
    // However, it might fail if the `t` is invalid somehow, although this
    // should only occur if there is an error in the caller or this library.
    t.serialize_uncompressed(&mut buf).unwrap();
    buf
}

pub fn deserialize<T: CanonicalDeserialize>(buf: &[u8]) -> T {
    T::deserialize_uncompressed(buf).unwrap()
}

pub fn bytes_to_field<F, const N: usize>(bytes: &[u8]) -> F 
    where F: PrimeField + From<BigInt<N>>
{
    F::from(BigInt::<N>::from_bits_le(bytes_to_bits(bytes).as_slice()))
}

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            let bit = (*byte >> i) & 1;
            bits.push(bit == 1);
        }
    }
    bits
}

// 1 at omega^i and 0 elsewhere on domain {omega^i}_{i \in [n]}
pub fn lagrange_poly<F: FftField + PrimeField>(
    n: usize, i: usize
) -> DensePolynomial<F> {
    //todo: check n is a power of 2
    let mut evals = vec![];
    for j in 0..n {
        let l_of_x: u64 = if i == j { 1 } else { 0 };
        evals.push(F::from(l_of_x));
    }

    //powers of nth root of unity
    let domain = Radix2EvaluationDomain::<F>::new(n).unwrap();
    let eval_form = Evaluations::from_vec_and_domain(evals, domain);
    //interpolated polynomial over the n points
    eval_form.interpolate()
}

/// returns t(X) = X^n - 1
pub fn compute_vanishing_poly<F: FftField + PrimeField + std::convert::From<u32>>(
    n: usize
) -> DensePolynomial<F> {
    let mut coeffs = vec![];
    for i in 0..n+1 {
        if i == 0 {
            coeffs.push(F::from(0u32) - F::from(1u32)); // -1
        } else if i == n {
            coeffs.push(F::from(1u32)); // X^n
        } else {
            coeffs.push(F::from(0u32));
        }
    }
    DensePolynomial { coeffs }
}

//computes c . f(x), for some constnt c
pub fn poly_eval_mult_const<F: FftField + PrimeField>(
    f: &DensePolynomial<F>, 
    c: &F
) -> DensePolynomial<F> {
    let mut new_poly = f.clone();
    for i in 0..(f.degree() + 1) {
        new_poly.coeffs[i] = new_poly.coeffs[i] * c.clone();
    }
    new_poly
}

// returns t(X) = c
pub fn compute_constant_poly<F: FftField + PrimeField>(
    c: &F
) -> DensePolynomial<F> {
    let mut coeffs = vec![];
    coeffs.push(c.clone()); // c
    DensePolynomial { coeffs }
}

//outputs f(ω x)
pub fn poly_domain_shift<F: FftField + PrimeField, const N: usize>(
    f: &DensePolynomial<F>,
    shift: usize
) -> DensePolynomial<F> {
    let domain = Radix2EvaluationDomain::<F>::new(N).unwrap();
    let ω = domain.group_gen;
    let k = ω.pow([shift as u64]);

    let mut new_poly = f.clone();
    for i in 1..(f.degree() + 1) { //we don't touch the zeroth coefficient
        let k_pow_i: F = k.pow([i as u64]);
        new_poly.coeffs[i] = new_poly.coeffs[i] * k_pow_i;
    }
    new_poly
}