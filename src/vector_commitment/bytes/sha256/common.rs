// SPDX-License-Identifier: Apache-2.0

use ark_crypto_primitives::{
    crh::{sha256::Sha256, CRHScheme, TwoToOneCRHScheme},
    Error,
};
use crate::merkle_tree::{Config, DigestConverter, MerkleTree};

pub type LeafH = Sha256;
pub type CompressH = Sha256;

pub struct CustomDigestConverter;

impl DigestConverter<Vec<u8>, [u8]> for CustomDigestConverter {
    type TargetType = Vec<u8>;

    fn convert(item: Vec<u8>) -> Result<Self::TargetType, Error> {
        Ok(item)
    }
}

pub struct Sha256MerkleTreeParams;

impl Config for Sha256MerkleTreeParams {
    type Leaf = [u8];

    type LeafDigest = <LeafH as CRHScheme>::Output;
    type LeafInnerDigestConverter = CustomDigestConverter;
    type InnerDigest = <CompressH as TwoToOneCRHScheme>::Output;

    type LeafHash = LeafH;
    type TwoToOneHash = CompressH;
}

pub type Sha256MerkleTree = MerkleTree<Sha256MerkleTreeParams>;