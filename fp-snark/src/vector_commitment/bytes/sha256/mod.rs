// SPDX-License-Identifier: Apache-2.0

pub mod common;
pub mod constraints;

use common::*;

use std::{collections::HashMap, marker::PhantomData};

use ark_crypto_primitives::{crh::{CRHScheme, TwoToOneCRHScheme}, to_uncompressed_bytes};
use crate::merkle_tree::{Config, Path};

use ark_std::rand::Rng;
use ark_serialize::CanonicalSerialize;
use ark_std::borrow::*;

#[derive(Clone)]
pub struct JZVectorCommitmentParams {
    pub leaf_crh_params: <LeafH as CRHScheme>::Parameters,
    pub two_to_one_params: <CompressH as TwoToOneCRHScheme>::Parameters,
}

impl JZVectorCommitmentParams {
    pub fn trusted_setup<R: Rng>(rng: &mut R) -> Self {
        let leaf_crh_params = <LeafH as CRHScheme>::setup(rng).unwrap();
        let two_to_one_params = <CompressH as TwoToOneCRHScheme>::setup(rng)
            .unwrap()
            .clone();

        JZVectorCommitmentParams {
            leaf_crh_params,
            two_to_one_params,
        }
    }
}

pub type JZVectorCommitmentPath = Path<Sha256MerkleTreeParams>;
pub type JZVectorCommitmentLeafDigest = <Sha256MerkleTreeParams as Config>::LeafDigest;
pub type JZVectorCommitmentInnerDigest = <Sha256MerkleTreeParams as Config>::InnerDigest;
pub type JZVectorCommitment = <Sha256MerkleTreeParams as Config>::InnerDigest;

pub struct JZVectorDB<L: CanonicalSerialize + Clone> {
    pub vc_params: JZVectorCommitmentParams,
    tree: Sha256MerkleTree,
    records: Vec<L>,
    marker: PhantomData<L>
}

#[derive(Clone)]
pub struct JZVectorCommitmentOpeningProof<L: CanonicalSerialize + Clone> {
    pub path: Path<Sha256MerkleTreeParams>,
    pub record: L,
    pub root: JZVectorCommitment
}

impl<L: CanonicalSerialize + Clone> JZVectorDB<L> {

    pub fn new(
        params: &JZVectorCommitmentParams,
        records: &[L]
    ) -> Self {

        let sha256_params = ();
        let leaves: Vec<Vec<u8>> = records
            .iter()
            .map(|leaf| {
                let mut leaf_bytes = Vec::new();
                leaf.serialize_uncompressed(&mut leaf_bytes).unwrap();
                leaf_bytes
            })
            .collect();

        let tree = Sha256MerkleTree::new(
            &sha256_params,
            &sha256_params,
            leaves.iter().map(|x| x.as_slice()),
        )
        .unwrap();

        let root = tree.root();

        // test merkle tree functionality without update
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof
                .verify(
                    &params.leaf_crh_params,
                    &params.two_to_one_params,
                    &root,
                    leaf.as_slice()
                ).unwrap()
            );
        }
        
        JZVectorDB {
            vc_params: params.clone(),
            tree,
            records: records.to_vec(),
            marker: PhantomData
        }
    }

    pub fn get_record(&self, index: usize) -> &L {
        if index >= self.records.len() {
            panic!("Index out of bounds");
        }

        &self.records[index]
    }

    pub fn update(&mut self, index: usize, record: &L) {
        if index >= self.records.len() {
            panic!("Index out of bounds");
        }

        self.records[index] = record.clone();
        let new_leaf = to_uncompressed_bytes!(record).unwrap();
        self.tree.update(index, &new_leaf).unwrap();
    }

    pub fn commitment(&self) -> JZVectorCommitment {
        self.tree.root()
    }

    pub fn proof(&self, index: usize) -> Path<Sha256MerkleTreeParams> {
        if index >= self.records.len() {
            panic!("Index out of bounds");
        }

        self.tree.generate_proof(index).unwrap()
    }

}

pub fn verify_vc_opening_proof<L: CanonicalSerialize>(
    params: &JZVectorCommitmentParams,
    commitment: &JZVectorCommitment,
    record: &L,
    proof: &Path<Sha256MerkleTreeParams>
) -> bool {
    let leaf = to_uncompressed_bytes!(record).unwrap();
    proof.verify(
        &params.leaf_crh_params,
        &params.two_to_one_params,
        commitment,
        leaf.as_slice()
    ).unwrap()
}

pub struct FrontierMerkleTreeWithHistory {
    pub levels: u32,
    pub root_history_size: u32,
    filled_subtrees: HashMap<u32, JZVectorCommitmentInnerDigest>,
    historical_roots: HashMap<u32, JZVectorCommitment>,
    current_root_index: u32,
    next_index: u32,
}

fn zeros(level: u32) -> JZVectorCommitmentInnerDigest {
    if level == 0 {
        // H([0; 32])
        return <LeafH as CRHScheme>::evaluate(&(), [0u8; 32]).unwrap();
    } else {
        // H(zeros(level - 1) || zeros(level - 1))
        let zeros_level_minus_1 = zeros(level - 1);
        return <CompressH as TwoToOneCRHScheme>::compress(
            &(),
            &zeros_level_minus_1,
            &zeros_level_minus_1
        ).unwrap()
    };
}

impl FrontierMerkleTreeWithHistory {

    // create a new merkle tree with no leaves
    pub fn new(
        levels: u32,
        root_history_size: u32,
    ) -> Self
    {
        assert!(levels > 0, "levels must be greater than 0");
        assert!(levels < 32, "levels must be less than 32");

        let mut filled_subtrees: HashMap<u32, JZVectorCommitmentInnerDigest> = HashMap::new();
        let mut historical_roots: HashMap<u32, JZVectorCommitment> = HashMap::new();

        for i in 0..levels {
            filled_subtrees.insert(i, zeros(i));
        }

        historical_roots.insert(0, zeros(levels - 1));

        FrontierMerkleTreeWithHistory {
            levels,
            root_history_size,
            filled_subtrees,
            historical_roots,
            current_root_index: 0,
            next_index: 0,
        }
    }

    // insert a new leaf into the merkle tree
    pub fn insert(&mut self, leaf: &JZVectorCommitmentLeafDigest) {
        assert!(self.next_index < (1 << self.levels), "Merkle tree is full");

        let mut current_index = self.next_index;

        let mut current_level_hash = leaf.clone();
        let mut left: JZVectorCommitmentInnerDigest;
        let mut right: JZVectorCommitmentInnerDigest;

        for i in 0..self.levels {
            if current_index % 2 == 0 { //left child
                left = current_level_hash.clone();
                right = zeros(i);
                self.filled_subtrees.insert(i, current_level_hash);
            } else { //right child
                left = self.filled_subtrees.get(&i).unwrap().clone();
                right = current_level_hash.clone();
            }

            current_level_hash = <CompressH as TwoToOneCRHScheme>::compress(
                &(),
                &left,
                &right
            ).unwrap();

            current_index /= 2;
        }

        let new_root_index = (self.current_root_index + 1) % self.root_history_size;
        self.current_root_index = new_root_index;
        self.historical_roots.insert(new_root_index, current_level_hash);
        self.next_index += 1;
    }

    pub fn is_known_root(&self, root: &JZVectorCommitment) -> bool {
        let current_root_index = self.current_root_index;
        let mut i = current_root_index;

        loop {
            if root == self.historical_roots.get(&i).unwrap() { return true; }
            if i == 0 { i = self.root_history_size; }
            i = i - 1;
            if i == current_root_index { break; }
        }

        return false;
    }

    pub fn get_latest_root(&self) -> JZVectorCommitment {
        self.historical_roots.get(&self.current_root_index).unwrap().clone()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::test_rng;
    use ark_ff::BigInteger256;
    use ark_bls12_377::*;

    #[test]
    fn test_vector_storage_bigint() {
        let mut rng = test_rng();
        let vc_params = JZVectorCommitmentParams::trusted_setup(&mut rng);

        let mut records = Vec::new();
        for x in 0..16u8 {
            records.push(BigInteger256::from(x));
        }

        let mut db = JZVectorDB::<BigInteger256>::new(&vc_params, &records);
        
        let com = db.commitment();
        let proof = db.proof(0);
        assert!(verify_vc_opening_proof(&vc_params, &com, &records[0], &proof));

        let updated_record = BigInteger256::from(42u8);
        db.update(1, &updated_record);
        let com = db.commitment();
        let proof = db.proof(1);
        assert!(verify_vc_opening_proof(&vc_params, &com, &updated_record, &proof));
    }

    #[test]
    fn test_vector_storage_g1() {
        let mut rng = test_rng();
        let vc_params = JZVectorCommitmentParams::trusted_setup(&mut rng);

        let mut records = Vec::new();
        // record i is g^i
        for x in 0..16u8 {
            let x_bi = BigInteger256::from(x);
            let g_pow_x_i = G1Affine::generator()
                .mul_bigint(x_bi)
                .into_affine();
            records.push(g_pow_x_i);
        }

        let db = JZVectorDB::<G1Affine>::new(&vc_params, &records);

        let com = db.commitment();
        let some_index = 5; //anything between 0 and 16
        let proof = db.proof(some_index);
        assert!(verify_vc_opening_proof(&vc_params, &com, &records[some_index], &proof));
    }
}

#[cfg(test)]
mod frontier_merkle_tree_tests {
    use super::*;

    #[test]
    fn test_frontier_merkle_tree() {
        let mut tree = FrontierMerkleTreeWithHistory::new(15, 30);

        for i in 0..3 {
            let leaf = <LeafH as CRHScheme>::evaluate(&(), [i as u8; 32]).unwrap();
            tree.insert(&leaf);
        }
    }

}

#[cfg(test)]
mod sha2_tests {

    use super::*;

    fn print_hash(hash: &Vec<u8>) {
        print!("[");
        hash.iter().for_each(|&x| { print!("{}, ", x); } );
        print!("],\n");
    }

    #[test]
    fn test_sha256() {
        let mut hash = <super::LeafH as CRHScheme>::
            evaluate(&(), [0u8; 32])
            .unwrap();

        print!("{} => ", 0); print_hash(&hash);

        for i in 1..32 {
            hash = <super::CompressH as TwoToOneCRHScheme>::
                compress(&(), &hash, &hash)
                .unwrap();

            print!("{} => ", i); print_hash(&hash);
        }

    }

}