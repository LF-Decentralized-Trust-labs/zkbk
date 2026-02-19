// SPDX-License-Identifier: Apache-2.0

pub mod constraints;
pub mod config;

use crate::merkle_tree::*;

use std::marker::PhantomData;
use ark_std::convert::*;

use ark_crypto_primitives::{crh::*, to_uncompressed_bytes};
use ark_std::rand::Rng;
use ark_serialize::CanonicalSerialize;
use ark_std::borrow::*;

pub struct JZVectorCommitmentParams<P: Config> 
{
    pub leaf_crh_params: <P::LeafHash as CRHScheme>::Parameters,
    pub two_to_one_params: <P::TwoToOneHash as TwoToOneCRHScheme>::Parameters,
}

impl<P: Config> JZVectorCommitmentParams<P> {
    pub fn trusted_setup<R: Rng>(rng: &mut R) -> Self {
        let leaf_crh_params = <P::LeafHash as CRHScheme>::setup(rng).unwrap();
        let two_to_one_params = <P::TwoToOneHash as TwoToOneCRHScheme>::setup(rng)
            .unwrap()
            .clone();

        JZVectorCommitmentParams {
            leaf_crh_params,
            two_to_one_params,
        }
    }
}

pub type JZVectorCommitment<P> = <P as Config>::InnerDigest;
pub type JZVectorCommitmentPath<P> = Path<P>;
pub type JZVectorCommitmentLeafDigest<P> = <P as Config>::LeafDigest;
pub type JZVectorCommitmentInnerDigest<P> = <P as Config>::InnerDigest;

pub struct JZVectorDB<P, L> 
    where   P: Config,
            L: CanonicalSerialize + Clone + Sized,
            [u8]: std::borrow::Borrow<<P as Config>::Leaf>,
            P: Config<Leaf = [u8]>
{
    pub vc_params: JZVectorCommitmentParams<P>,
    tree: MerkleTree<P>,
    records: Vec<L>,
    marker: PhantomData<L>
}

#[derive(Clone)]
pub struct JZVectorCommitmentOpeningProof<P, L>
    where   P: Config,
            L: CanonicalSerialize + Clone + Sized,
            [u8]: std::borrow::Borrow<<P as Config>::Leaf>,
            P: Config<Leaf = [u8]>
{
    pub path: Path<P>,
    pub record: L,
    pub root: JZVectorCommitment<P>
}

impl<P, L> JZVectorDB<P, L> 
    where   P: Config,
            L: CanonicalSerialize + Clone + Sized,
            [u8]: std::borrow::Borrow<<P as Config>::Leaf>,
            P: Config<Leaf = [u8]>
{

    pub fn new(
        params: JZVectorCommitmentParams<P>,
        records: &[L]
    ) -> Self {

        let leaves: Vec<Vec<u8>> = records
            .iter()
            .map(|leaf| to_uncompressed_bytes!(leaf).unwrap())
            .collect();

        let tree = MerkleTree::<P>::new(
            &params.leaf_crh_params.clone(),
            &params.two_to_one_params.clone(),
            leaves.iter().map(|x| x.as_slice()),
        )
        .unwrap();

        let root = tree.root();

        // test merkle tree functionality without update
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify::<Vec<u8>>(
                    &params.leaf_crh_params,
                    &params.two_to_one_params,
                    &root,
                    leaf.as_slice().to_owned()
                ).unwrap()
            );
        }
        
        JZVectorDB::<P,L> {
            vc_params: params,
            tree,
            records: records.to_vec(),
            marker: PhantomData
        }
    }

    pub fn get_record(&self, index: usize) -> &L {
        if index >= self.records.len() {
            panic!("Index out of bounds: {}", index);
        }

        &self.records[index]
    }

    pub fn update(&mut self, index: usize, record: &L) {
        if index >= self.records.len() {
            panic!("Index out of bounds: {}", index);
        }

        self.records[index] = record.clone();
        let new_leaf = to_uncompressed_bytes!(record).unwrap();
        self.tree.update(index, &new_leaf).unwrap();
    }

    pub fn commitment(&self) -> JZVectorCommitment<P> {
        self.tree.root()
    }

    pub fn proof(&self, index: usize) -> Path<P> {
        if index >= self.records.len() {
            panic!("Index out of bounds");
        }

        self.tree.generate_proof(index).unwrap()
    }

}

pub fn verify_proof<P, L>
(
    params: &JZVectorCommitmentParams<P>,
    commitment: &JZVectorCommitment<P>,
    record: &L,
    proof: &Path<P>
) -> bool 
    where   P: Config,
            L: CanonicalSerialize + Clone + Sized,
            [u8]: std::borrow::Borrow<<P as Config>::Leaf>,
            P: Config<Leaf = [u8]>
{
    let leaf = to_uncompressed_bytes!(record).unwrap();
    proof.verify(
        &params.leaf_crh_params,
        &params.two_to_one_params,
        commitment,
        leaf
    ).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::BigInteger256;
    use ark_bls12_377::*;
    use rand::SeedableRng;

    type MT = config::ed_on_bw6_761::MerkleTreeParams;

    fn generate_vc_params<P: crate::merkle_tree::Config>() -> JZVectorCommitmentParams<P> {
        let seed = [0u8; 32];
        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);
        JZVectorCommitmentParams::<P>::trusted_setup(&mut rng)
    }

    #[test]
    fn test_vector_storage_bigint() {

        let mut records = Vec::new();
        for x in 0..16u8 {
            records.push(BigInteger256::from(x));
        }

        let mut db = JZVectorDB::<MT, BigInteger256>::new(
            generate_vc_params::<MT>(), &records
        );
        
        let com = db.commitment();
        let proof = db.proof(0);
        assert!(verify_proof(&generate_vc_params::<MT>(), &com, &records[0], &proof));

        let updated_record = BigInteger256::from(42u8);
        db.update(1, &updated_record);
        let com = db.commitment();
        let proof = db.proof(1);
        assert!(verify_proof(&generate_vc_params::<MT>(), &com, &updated_record, &proof));
    }

    #[test]
    fn test_vector_storage_g1() {

        let mut records = Vec::new();
        // record i is g^i
        for x in 0..16u8 {
            let x_bi = BigInteger256::from(x);
            let g_pow_x_i = G1Affine::generator()
                .mul_bigint(x_bi)
                .into_affine();
            records.push(g_pow_x_i);
        }

        let db = JZVectorDB::<MT, G1Affine>::new(generate_vc_params::<MT>(), &records);

        let com = db.commitment();
        let some_index = 5; //anything between 0 and 16
        let proof = db.proof(some_index);
        assert!(verify_proof(&generate_vc_params::<MT>(), &com, &records[some_index], &proof));
    }
}