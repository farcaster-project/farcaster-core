//! Defines the high level of a swap between a Arbitrating blockchain and an Accordant blockchain.

use std::fmt::Debug;
use std::io;

use crate::consensus::{self, CanonicalBytes, Decodable, Encodable};
use crate::crypto::Commitment;
use crate::role::{Accordant, Arbitrating};

use lightning_encoding::strategies::AsStrict;
use serde::{Deserialize, Serialize};

fixed_hash::construct_fixed_hash!(
    /// A unique swap identifier represented as an 32 bytes hash.
    #[derive(Serialize, Deserialize)]
    pub struct SwapId(32);
);

impl Encodable for SwapId {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(s)
    }
}

impl Decodable for SwapId {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let bytes: [u8; 32] = Decodable::consensus_decode(d)?;
        Ok(Self::from_slice(&bytes))
    }
}

impl_strict_encoding!(SwapId);

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
