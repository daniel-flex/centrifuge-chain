use codec::{Decode, Encode};
use sp_std::vec::Vec;

#[derive(Encode, Decode, Default, Clone, PartialEq)]
#[cfg_attr(not(feature = "std"), derive(sp_runtime::RuntimeDebug))]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Proof<Hash> {
    leaf_hash: Hash,
    sorted_hashes: Vec<Hash>,
}

pub trait Hasher: Sized {
    // Hash type we deal with
    type Hash: Default + AsRef<[u8]> + From<[u8; 32]> + Copy + PartialEq;

    /// Hashes given data to 32 byte u8. Ex: blake256, Keccak
    fn hash(data: &[u8]) -> [u8; 32];

}

pub trait Verifier: Hasher {
    /// Returns the initial set of hashes to verify proofs.
    /// `None` implies a failed proof verification
    fn initial_matches(doc_root: Self::Hash) -> Option<Vec<Self::Hash>>;

    /// Computes hash of the a + b using `hash` function
    fn hash_of(a: Self::Hash, b: Self::Hash) -> Self::Hash {
        let size = a.as_ref().len() + b.as_ref().len();
        let mut h: Vec<u8> = Vec::with_capacity(size);
        h.extend_from_slice(a.as_ref());
        h.extend_from_slice(b.as_ref());
        Self::hash(&h).into()
    }

    /// Validates each proof and return true if all the proofs are valid else returns false
    fn validate_proofs(doc_root: Self::Hash, proofs: &Vec<Proof<Self::Hash>>) -> bool {
        if proofs.len() < 1 {
            return false;
        }

        let mut matches = match Self::initial_matches(doc_root) {
            Some(matches)=> matches,
            None => return false
        };

        proofs
            .iter()
            .map(|proof| helpers::validate_proof::<Self>(&mut matches, proof))
            .fold(true, |acc, b| acc && b)
    }

    /// Validates the proof and returns true if valid
    fn validate_proof(doc_root: Self::Hash, proof: &Proof<Self::Hash>) -> bool {
        let mut matches = match Self::initial_matches(doc_root) {
            Some(matches)=> matches,
            None => return false
        };

        helpers::validate_proof::<Self>(&mut matches, proof)
    }
}

pub trait BundleHasher: Hasher {
    /// Appends deposit_address and all the hashes from the proofs and returns the result hash
    fn bundled_hash(proofs: Vec<Proof<Self::Hash>>, deposit_address: [u8; 20]) -> Self::Hash {
        let hash = proofs
            .into_iter()
            .fold(deposit_address.to_vec(), |mut acc, proof| {
                acc.extend_from_slice(&proof.leaf_hash.as_ref());
                acc
            });
        Self::hash(hash.as_slice()).into()
    }
}

mod helpers {
    use crate::*;

    /// This is an optimized Merkle proof checker. It caches all valid leaves in an array called
    /// matches. If a proof is validated, all the intermediate hashes will be added to the array.
    /// When validating a subsequent proof, that proof will stop being validated as soon as a hash
    /// has been computed that has been a computed hash in a previously validated proof.
    ///
    /// When submitting a list of proofs, the client can thus choose to chop of all the already proven
    /// nodes when submitting multiple proofs.
    ///
    /// matches: matches will have a pre computed hashes provided by the client and document root of the
    /// reference anchor. static proofs are used to computed the pre computed hashes and the result is
    /// checked against document root provided.
    pub fn validate_proof<V: Verifier>(matches: &mut Vec<V::Hash>, proof: &Proof<V::Hash>) -> bool {
        let Proof{leaf_hash,sorted_hashes} = proof.clone();

        // if leaf_hash is already cached/computed earlier
        if matches.contains(&leaf_hash) {
            return true;
        }

        let mut hash = leaf_hash;
        for proof in sorted_hashes {
            matches.push(proof.clone());
            hash = V::hash_of(hash.clone(), proof.clone());
            if matches.contains(&hash) {
                return true;
            }
            matches.push(hash);
        }

        return false;
    }
}
