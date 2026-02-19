// SPDX-License-Identifier: Apache-2.0

pub mod constraints;
pub mod config;

use ark_crypto_primitives::crh::CRHScheme;
use ark_std::rand::Rng;
use ark_serialize::*;
use std::io::Cursor;


#[derive(Derivative)]
#[derivative(Clone(bound = "H: CRHScheme"))]
pub struct JZPRFParams<H: CRHScheme> {
    pub crh_params: <H as CRHScheme>::Parameters,
}

impl<H: CRHScheme> JZPRFParams<H> {
    pub fn trusted_setup<R: Rng>(rng: &mut R) -> Self {
        JZPRFParams {
            crh_params: <H as CRHScheme>::setup(rng).unwrap(),
        }
    }
}

pub struct JZPRFInstance<H: CRHScheme>
    where   Vec<u8>: std::borrow::Borrow<<H as CRHScheme>::Input>,
{
    pub params: JZPRFParams<H>,
    pub input: Vec<u8>,
    pub key: Vec<u8>,
}

impl<H: CRHScheme> JZPRFInstance<H>
    where   Vec<u8>: std::borrow::Borrow<<H as CRHScheme>::Input>,
{
    pub fn new(
        params: &JZPRFParams<H>,
        input: &[u8],
        key: &[u8],
    ) -> Self {
        JZPRFInstance {
            params: params.clone(),
            input: input.to_vec(),
            key: key.to_vec(),
        }
    }

    pub fn evaluate(&self) -> Vec<u8> {
        let mut prf_input = vec![];
        prf_input.extend_from_slice(&self.input);
        prf_input.extend_from_slice(&self.key);

        let crh_output: <H as CRHScheme>::Output =
            <H as CRHScheme>::evaluate(
                &self.params.crh_params,
                prf_input
            )
            .unwrap();

        // the output of the PRF only contains the x coordinate
        let mut serialized = vec![0; crh_output.serialized_size(ark_serialize::Compress::No)];
        let mut cursor = Cursor::new(&mut serialized[..]);
        crh_output.serialize_uncompressed(&mut cursor).unwrap();

        serialized
    }
}

#[cfg(test)]
mod tests {
    use crate::prf::*;
    use rand::SeedableRng;

    type H = config::ed_on_bw6_761::Hash;

    #[test]
    fn test_jzprf() {
        let seed = [0u8; 32];
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);
        let prf_params = JZPRFParams::<H>::trusted_setup(&mut rng);
        
        let input = [0u8; 32];
        let key = [25u8; 32];

        let instance = JZPRFInstance::<H>::new(&prf_params, &input, &key);
        let _prf_output = instance.evaluate();
    }
}
