use strict_encoding::{StrictDecode, StrictEncode};

use farcaster_core::crypto::DleqProof;
use farcaster_core::swap::Swap;

use crate::bitcoin::Bitcoin;
use crate::monero::Monero;

pub struct BtcXmr;

impl Swap for BtcXmr {
    /// The arbitrating blockchain
    type Ar = Bitcoin;

    /// The accordant blockchain
    type Ac = Monero;

    /// The proof system to link both cryptographic groups
    type Proof = RingProof;
}

#[derive(Clone, Debug)]
pub struct RingProof;

impl DleqProof<Bitcoin, Monero> for RingProof {}

impl StrictEncode for RingProof {
    fn strict_encode<E: std::io::Write>(&self, mut _e: E) -> Result<usize, strict_encoding::Error> {
        Ok(0)
    }
}

impl StrictDecode for RingProof {
    fn strict_decode<D: std::io::Read>(mut _d: D) -> Result<Self, strict_encoding::Error> {
        Ok(Self)
    }
}
