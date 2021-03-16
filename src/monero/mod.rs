//! Defines and implements all the traits for Monero

use std::fmt::{self, Debug, Display, Formatter};
use bitcoin::hash_types::PubkeyHash;  // DELETEME encoding test
use monero::cryptonote::hash::Hash;
use monero::util::key::PrivateKey;
use monero::util::key::PublicKey;

use crate::blockchain::Blockchain;
use crate::crypto::{Commitment, Curve, Keys};
use crate::role::Accordant;

#[derive(Debug, Clone, Copy)]
pub struct Monero;

impl Display for Monero {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        println!("xmr");
        Ok(())
    }
}

impl Blockchain for Monero {
    /// Type for the traded asset unit
    type AssetUnit = u64;

    /// Create a new Bitcoin blockchain
    fn new() -> Self {
        Monero {}
    }

    fn from_u32(bytes: u32) -> Option<Self> {
        match bytes {
            0x80000080 => Some(Self::new()),
            _ => None,
        }
    }

    fn to_u32(&self) -> u32 {
        0x80000080
    }
}

pub struct Ed25519;

impl Curve for Monero {
    type Curve = Ed25519;
}

impl Accordant for Monero {}

impl Keys for Monero {
    /// Private key type for the blockchain
    type PrivateKey = PrivateKey;

    /// Public key type for the blockchain
    type PublicKey = PublicKey;
}

impl Commitment for Monero {
    type Commitment = PubkeyHash;
}
