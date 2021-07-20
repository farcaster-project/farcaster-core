//! Defines the high level of a swap between a Arbitrating blockchain and an Accordant blockchain.

use std::fmt::Debug;

use crate::consensus::CanonicalBytes;
use crate::crypto::Commitment;
use crate::role::{Accordant, Arbitrating};

fixed_hash::construct_fixed_hash!(
    /// A unique swap identifier represented as an 32 bytes hash.
    pub struct SwapId(32);
);

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
