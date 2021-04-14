//! Defines and implements all the traits for Monero

use farcaster_core::blockchain::Asset;
use farcaster_core::crypto::{
    AccordantKey, Commitment, FromSeed, Keys, SharedPrivateKey, SharedPrivateKeys,
};
use farcaster_core::role::{Acc, Accordant};

use monero::cryptonote::hash::Hash;
use monero::util::key::{PrivateKey, PublicKey};

use std::fmt::{self, Debug, Display, Formatter};

pub const SHARED_KEY_BITS: usize = 252;

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

impl Asset for Monero {
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

    fn as_bytes(pubkey: &PublicKey) -> Vec<u8> {
        pubkey.as_bytes().into()
    }
}

impl SharedPrivateKeys<Acc> for Monero {
    type SharedPrivateKey = PrivateKey;

    fn get_shared_privkey(seed: &[u8; 32], key_type: SharedPrivateKey) -> PrivateKey {
        match key_type {
            SharedPrivateKey::View => {
                let mut bytes = Vec::from(b"farcaster_priv_view".as_ref());
                bytes.extend_from_slice(&seed.as_ref());
                Hash::hash(&bytes).as_scalar()
            }
        }
    }

    fn as_bytes(privkey: &PrivateKey) -> Vec<u8> {
        privkey.as_bytes().into()
    }
}

impl Commitment for Monero {
    type Commitment = Hash;

    fn commit_to<T: AsRef<[u8]>>(value: T) -> Hash {
        Hash::hash(value.as_ref())
    }
}

pub fn private_spend_from_seed<T: AsRef<[u8]>>(seed: T) -> PrivateKey {
    let mut bytes = Vec::from(b"farcaster_priv_spend".as_ref());
    bytes.extend_from_slice(&seed.as_ref());

    let mut key = Hash::hash(&bytes).to_fixed_bytes();
    key[31] &= 0b0000_1111; // Chop off bits that might be greater than the curve modulus

    PrivateKey::from_slice(&key).unwrap()
}

impl FromSeed<Acc> for Monero {
    type Seed = [u8; 32];

    fn get_pubkey(seed: &[u8; 32], key_type: AccordantKey) -> PublicKey {
        match key_type {
            AccordantKey::Spend => PublicKey::from_private_key(&private_spend_from_seed(&seed)),
        }
    }
}
