// SPDX-License-Identifier: Apache-2.0
// Portions of this file are derived from arkworks-rs/r1cs-tutorial under Apache 2.0 License.

use super::SignatureScheme;
use ark_crypto_primitives::Error;
use ark_ec::CurveGroup;
use ark_ff::fields::PrimeField;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{ops::*, hash::Hash, marker::PhantomData, vec::Vec, rand::Rng};
use blake2::Blake2s;
use digest::Digest;

use crate::utils;
pub mod constraints;

pub struct Schnorr<C: CurveGroup> {
    _group: PhantomData<C>,
}

#[derive(Clone, Default, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct Parameters<C: CurveGroup> {
    pub generator: C::Affine,
    pub salt: Option<[u8; 32]>,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

#[derive(Clone, Default, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct SecretKey<C: CurveGroup> {
    pub secret_key: C::ScalarField,
    pub public_key: PublicKey<C>,
}

#[derive(Clone, Default, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct Signature<C: CurveGroup> {
    pub prover_response: C::ScalarField,
    pub verifier_challenge: [u8; 32],
}

impl<C: CurveGroup + Hash> SignatureScheme for Schnorr<C>
where
    C::ScalarField: PrimeField,
{
    type Parameters = Parameters<C>;
    type PublicKey = PublicKey<C>;
    type SecretKey = SecretKey<C>;
    type Signature = Signature<C>;

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        let salt = None;
        let generator = C::generator().into();

        Ok(Parameters { generator, salt })
    }

    fn keygen<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        // Secret is a random scalar x
        // the pubkey is y = xG
        let secret_key = C::ScalarField::rand(rng);
        let public_key = parameters.generator.mul(secret_key).into();

        Ok((
            public_key,
            SecretKey {
                secret_key,
                public_key,
            },
        ))
    }

    fn sign<R: Rng>(
        parameters: &Self::Parameters,
        sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, Error> {
        // (k, e);
        let (random_scalar, verifier_challenge) = {
            // Sample a random scalar `k` from the prime scalar field.
            let random_scalar: C::ScalarField = C::ScalarField::rand(rng);
            // Commit to the random scalar via r := k · G.
            // This is the prover's first msg in the Sigma protocol.
            let prover_commitment = parameters.generator.mul(random_scalar).into_affine();

            // Hash everything to get verifier challenge.
            // e := H(salt || pubkey || r || msg);
            let mut hash_input = Vec::new();
            if parameters.salt != None {
                hash_input.extend_from_slice(&parameters.salt.unwrap());
            }
            hash_input.extend_from_slice(&utils::serialize(&sk.public_key));
            hash_input.extend_from_slice(&utils::serialize(&prover_commitment));
            hash_input.extend_from_slice(message);

            let hash_digest = Blake2s::digest(&hash_input);
            assert!(hash_digest.len() >= 32);
            let mut verifier_challenge = [0u8; 32];
            verifier_challenge.copy_from_slice(&hash_digest);

            (random_scalar, verifier_challenge)
        };

        let verifier_challenge_fe = C::ScalarField::from_le_bytes_mod_order(&verifier_challenge);

        // k - xe;
        let prover_response = random_scalar - (verifier_challenge_fe * sk.secret_key);
        let signature = Signature {
            prover_response,
            verifier_challenge,
        };

        Ok(signature)
    }

    fn verify(
        parameters: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
        let Signature {
            prover_response,
            verifier_challenge,
        } = signature;
        let verifier_challenge_fe = C::ScalarField::from_le_bytes_mod_order(verifier_challenge);
        // sG = kG - eY
        // kG = sG + eY
        // so we first solve for kG.
        let mut claimed_prover_commitment = parameters.generator.mul(*prover_response);
        let public_key_times_verifier_challenge = pk.mul(verifier_challenge_fe);
        claimed_prover_commitment += &public_key_times_verifier_challenge;
        let claimed_prover_commitment = claimed_prover_commitment.into_affine();

        // e = H(salt, kG, msg)
        let mut hash_input = Vec::new();
        if parameters.salt != None {
            hash_input.extend_from_slice(&parameters.salt.unwrap());
        }
        hash_input.extend_from_slice(&utils::serialize(pk));
        hash_input.extend_from_slice(&utils::serialize(&claimed_prover_commitment));
        hash_input.extend_from_slice(message);

        // cast the hash output to get e
        let obtained_verifier_challenge = &Blake2s::digest(&hash_input)[..];
        // end_timer!(verify_time);
        // The signature is valid iff the computed verifier challenge is the same as the one
        // provided in the signature
        Ok(verifier_challenge == obtained_verifier_challenge)
    }
}

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            let bit = (*byte >> (8 - i - 1)) & 1;
            bits.push(bit == 1);
        }
    }
    bits
}
