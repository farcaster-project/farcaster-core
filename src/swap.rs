//! Defines the high level of a swap between a Arbitrating blockchain and an Accordant blockchain.

use std::fmt::Debug;

use crate::consensus::CanonicalBytes;
use crate::crypto::Commitment;
use crate::role::{Accordant, Arbitrating};
use lightning_encoding::strategies::AsStrict;

fixed_hash::construct_fixed_hash!(
    /// A unique swap identifier represented as an 32 bytes hash.
    pub struct SwapId(32);
);

///// This did not work on the node
// impl strict_encoding::Strategy for SwapId {
//     type Strategy =  HashFixedBytes;
// }

impl strict_encoding::StrictEncode for SwapId {
    fn strict_encode<E: std::io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
       e.write_all(&self[..])?;
       Ok(32)
    }
}

impl strict_encoding::StrictDecode for SwapId {
    fn strict_decode<D: std::io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        let mut buf = vec![0u8; 32];
        d.read_exact(&mut buf)?;
        Ok(Self::from_slice(&buf))
    }
}

impl lightning_encoding::Strategy for SwapId {
    type Strategy = AsStrict;
}

/// Specifie the context of a swap, fixing the arbitrating blockchain, the accordant blockchain and
/// the link between them.
pub trait Swap: Debug + Clone + Commitment {
    /// The arbitrating blockchain concrete implementation used for the swap.
    type Ar: Arbitrating;

    /// The accordant blockchain concrete implementation used for the swap.
    type Ac: Accordant;

    ///// The concrete type to link both blockchain cryptographic groups used in by the signatures.
    type Proof: Clone + Debug + CanonicalBytes;
}
