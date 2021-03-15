//! Defines the high level of a swap between a Arbitrating blockchain and an Accordant blockchain.

use crate::crypto::CrossGroupDLEQ;
use crate::role::{Accordant, Arbitrating};

/// Specifies the entire swap, with a pair of Arbitrating and Accordant chains, and their eliptic
/// curves, and their cross-group equality.
pub trait Swap<Ar, Ac>: CrossGroupDLEQ<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
    Ar::Curve: PartialEq<Ac::Curve>,
    Ac::Curve: PartialEq<Ar::Curve>,
{
}
