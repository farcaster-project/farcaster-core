//! Defines and implements all the traits for Monero

use farcaster_core::blockchain::Blockchain;
use farcaster_core::crypto::{Commitment, Curve, Keys, PrivateViewKey};
use farcaster_core::role::Accordant;

use bitcoin::hash_types::PubkeyHash; // DELETEME encoding test

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

#[derive(Clone, Debug)]
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

impl PrivateViewKey for Monero {
    type PrivateViewKey = PrivateKey;
}

impl Commitment for Monero {
    type Commitment = PubkeyHash;
}

use strict_encoding::{StrictDecode, StrictEncode};
impl StrictEncode for Ed25519 {
    fn strict_encode<E: std::io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        let res = Hash::hash(&"Farcaster Ed25519".as_bytes()).to_bytes();
        e.write(&res)?;
        Ok(res.len())
    }
}

impl StrictDecode for Ed25519 {
    fn strict_decode<D: std::io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        let mut buf = [0u8; 32];
        d.read_exact(&mut buf)?;
        let expected = Hash::hash(&"Farcaster Ed25519".as_bytes()).to_bytes();
        if expected == buf {
            Ok(Self)
        } else {
            Err(strict_encoding::Error::DataIntegrityError(
                "Not Ed25519 type".to_string(),
            ))
        }
    }
}
