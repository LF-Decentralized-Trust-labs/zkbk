pub mod flipped;
pub mod standard;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::{test_rng, UniformRand};

    #[test]
    fn test_standard_gro15() {
        let rng = &mut test_rng();
        type E = Bls12_381;

        let params = standard::Params::<E>::new(rng);
        let (vk, sk) = standard::SecretKey::new(&params, rng);

        let m1 = <E as Pairing>::G2::rand(rng);
        let m2 = <E as Pairing>::G2::rand(rng);

        let sig = sk.sign(&params, &m1, &m2, rng);
        let valid = vk.verify(&params, &m1, &m2, &sig);

        assert!(valid, "Standard Gro15 verification failed");
    }

    #[test]
    fn test_flipped_gro15() {
        let rng = &mut test_rng();
        type E = Bls12_381;

        let params = flipped::Params::<E>::new(rng);
        let (vk, sk) = flipped::SecretKey::new(&params, rng);

        let m1 = <E as Pairing>::G1::rand(rng);
        let m2 = <E as Pairing>::G1::rand(rng);

        let sig = sk.sign(&params, &m1, &m2, rng);
        let valid = vk.verify(&params, &m1, &m2, &sig);

        assert!(valid, "Flipped Gro15 verification failed");
    }
}
