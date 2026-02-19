// SPDX-License-Identifier: Apache-2.0

use ark_crypto_primitives::crh::{pedersen, *};
use ark_r1cs_std::uint8::UInt8;

use crate::merkle_tree::*;
use crate::merkle_tree::constraints::{BytesVarDigestConverter, ConfigGadget};

#[derive(Clone)]
pub struct Window4x256;
impl pedersen::Window for Window4x256 {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}

type JubJubProjective = ark_ed_on_bls12_377::EdwardsProjective;
type JubJubAffineVar = ark_ed_on_bls12_377::constraints::EdwardsVar;
type ConstraintF = ark_bls12_377::Fr;

#[derive(Clone)]
pub struct MerkleTreeParams;

impl Config for MerkleTreeParams {
    type Leaf = [u8];

    type LeafDigest = <pedersen::CRH<JubJubProjective, Window4x256> as CRHScheme>::Output;
    type LeafInnerDigestConverter = ByteDigestConverter<Self::LeafDigest>;
    type InnerDigest = <pedersen::TwoToOneCRH<JubJubProjective, Window4x256> as TwoToOneCRHScheme>::Output;

    type LeafHash = pedersen::CRH<JubJubProjective, Window4x256>;
    type TwoToOneHash = pedersen::TwoToOneCRH<JubJubProjective, Window4x256>;
}

pub struct MerkleTreeParamsVar;

impl ConfigGadget<MerkleTreeParams, ConstraintF> for MerkleTreeParamsVar {
    type Leaf = [UInt8<ConstraintF>];

    type LeafDigest = <Self::LeafHash as CRHSchemeGadget<<MerkleTreeParams as Config>::LeafHash, ConstraintF>>::OutputVar;
    type LeafInnerConverter = BytesVarDigestConverter<Self::LeafDigest, ConstraintF>;
    type InnerDigest = <Self::TwoToOneHash as TwoToOneCRHSchemeGadget<<MerkleTreeParams as Config>::TwoToOneHash, ConstraintF>>::OutputVar;

    type LeafHash = pedersen::constraints::CRHGadget<JubJubProjective, JubJubAffineVar, Window4x256>;
    type TwoToOneHash = pedersen::constraints::TwoToOneCRHGadget<JubJubProjective, JubJubAffineVar, Window4x256>;
}
