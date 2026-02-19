use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::One; // For One::one()
use ark_poly::DenseUVPolynomial; // For from_coefficients_vec
use ark_std::{test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion};
use fp_blackbox::gro15::{flipped, standard};
use fp_blackbox::vouch::{credential::Credential, params::PublicParams, proof::Proof};

type E = Bls12_381;
const MAX_DEGREE: usize = 10;

fn vouch_workflow_benchmark(c: &mut Criterion) {
    let mut rng = test_rng();

    // Setup (Common for all benchmarks)
    let pp = PublicParams::<E>::new(MAX_DEGREE, &mut rng);

    // Issuer KeyGen
    // 0. KeyGen Benchmarks
    c.bench_function("issuer_keygen", |b| {
        b.iter(|| standard::SecretKey::new(&pp.gro15_params, &mut rng))
    });

    // User KeyGen
    c.bench_function("user_keygen", |b| {
        b.iter(|| flipped::SecretKey::new(&pp.flipped_params, &mut rng))
    });

    // Prepare keys for later steps (already done above but included for flow)
    let (issuer_pk, issuer_sk) = standard::SecretKey::new(&pp.gro15_params, &mut rng);

    // User KeyGen
    let (user_vk, user_sk) = flipped::SecretKey::new(&pp.flipped_params, &mut rng);
    let user_proof = user_sk.prove_knowledge(&pp.flipped_params, &mut rng);

    // Prepare attributes (e.g., 5 attributes)
    let attributes: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();

    // 1. Issue Credential
    c.bench_function("issue_credential", |b| {
        b.iter(|| {
            Credential::issue(
                &pp,
                &issuer_sk,
                &user_vk,
                &user_proof,
                &attributes,
                &mut rng,
            )
            .unwrap()
        })
    });

    // Generate a credential for subsequent steps
    let mut credential = Credential::issue(
        &pp,
        &issuer_sk,
        &user_vk,
        &user_proof,
        &attributes,
        &mut rng,
    )
    .unwrap();
    // Set user secret key for vouching
    credential.v_u_sk = Some(user_sk.clone());

    // 2. Vouch Generation
    // Hide attributes at index 0 and 2. Reveal 1, 3, 4.
    let revealed_indices = vec![1, 3, 4];
    let statement = Fr::rand(&mut rng);

    c.bench_function("generate_vouch", |b| {
        b.iter(|| credential.vouch(&pp, &attributes, &revealed_indices, &statement, &mut rng))
    });

    // Generate a vouch for subsequent steps
    let vouch = credential.vouch(&pp, &attributes, &revealed_indices, &statement, &mut rng);

    // 3. GS Proof Generation
    // Prepare inputs for proof
    let pk = fp_blackbox::gs08::ProverKey::<E>::setup(&mut rng);

    // Reconstruct M2 and KZG pi
    let (m2_poly_val, kzg_pi) = {
        let mut subset_poly =
            ark_poly::univariate::DensePolynomial::from_coefficients_vec(vec![Fr::one()]);
        for &val in &vouch.revealed_values {
            let poly_i =
                ark_poly::univariate::DensePolynomial::from_coefficients_vec(vec![-val, Fr::one()]);
            use std::ops::Mul;
            subset_poly = subset_poly.mul(&poly_i);
        }
        let m2 = pp.commit_g1(&subset_poly);

        let poly = fp_blackbox::vouch::credential::compute_polynomial(&attributes);
        use std::ops::Div;
        let q_poly = poly.div(&subset_poly);
        let kzg_pi = pp.commit_g2(&q_poly);
        (m2, kzg_pi)
    };

    // User VK for GS (flipped VK struct)
    // credential.v_u is the G2 element.
    let user_vk_flipped = flipped::VerificationKey { v: credential.v_u };

    c.bench_function("gs_prove", |b| {
        b.iter(|| {
            Proof::prove(
                &pp,
                &pk,
                &vouch,
                &credential,
                &user_vk_flipped,
                &m2_poly_val,
                &kzg_pi,
                &mut rng,
            )
        })
    });

    let gs_proof = Proof::prove(
        &pp,
        &pk,
        &vouch,
        &credential,
        &user_vk_flipped,
        &m2_poly_val,
        &kzg_pi,
        &mut rng,
    );

    // 4. GS Proof Verification
    // Use standard issuer VK
    // issuer_pk is standard::VerificationKey
    c.bench_function("gs_verify", |b| {
        b.iter(|| gs_proof.verify(&pp, &pk, &issuer_pk, &statement, &m2_poly_val))
    });
}

criterion_group!(benches, vouch_workflow_benchmark);
criterion_main!(benches);
