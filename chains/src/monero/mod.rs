//! Defines and implements all the traits for Monero

use farcaster_core::blockchain::Blockchain;
use farcaster_core::crypto::{Commitment, Keys, ShareablePrivateKeys};
use farcaster_core::role::Accordant;

use monero::cryptonote::hash::Hash;
use monero::util::key::PrivateKey;
use monero::util::key::PublicKey;

use std::fmt::{self, Debug, Display, Formatter};

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct Monero;

impl std::str::FromStr for Monero {
    type Err = farcaster_core::consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Monero" => Ok(Monero),
            _ => Err(farcaster_core::consensus::Error::UnknownType),
        }
    }
}

impl Display for Monero {
    fn fmt(&self, _f: &mut Formatter<'_>) -> fmt::Result {
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

impl Accordant for Monero {}

impl Keys for Monero {
    /// Private key type for the blockchain
    type PrivateKey = PrivateKey;

    /// Public key type for the blockchain
    type PublicKey = PublicKey;
}

impl ShareablePrivateKeys for Monero {
    type ShareablePrivateKey = PrivateKey;
}

impl Commitment for Monero {
    type Commitment = Hash;
}
