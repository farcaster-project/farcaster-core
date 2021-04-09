//! Defines the high level of a swap between a Arbitrating blockchain and an Accordant blockchain.

use crate::crypto::DleqProof;
use crate::role::{Accordant, Arbitrating};

/// Specifie the context of a swap, fixing the arbitrating blockchain, the accordant blockchain and
/// the link between them.
pub trait Swap {
    /// The arbitrating blockchain concrete implementation used for the swap.
    type Ar: Arbitrating;

    /// The accordant blockchain concrete implementation used for the swap.
    type Ac: Accordant;

    /// The concrete type to link both blockchain cryptographic groups used in by the signatures.
    type Proof: DleqProof<Self::Ar, Self::Ac>;
}
