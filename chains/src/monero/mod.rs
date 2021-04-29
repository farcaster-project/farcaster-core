//! Defines and implements all the traits for Monero

use farcaster_core::blockchain::Asset;
use farcaster_core::crypto::{
    self, AccordantKey, FromSeed, Keys, SharedPrivateKey, SharedPrivateKeys,
};
use farcaster_core::role::{Acc, Accordant};

use monero::cryptonote::hash::Hash;
use monero::util::key::{PrivateKey, PublicKey};

use async_trait::async_trait;

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

#[async_trait]
impl SharedPrivateKeys<Acc> for Monero {
    type SharedPrivateKey = PrivateKey;

    async fn get_shared_privkey(
        engine: &Wallet,
        key_type: SharedPrivateKey,
    ) -> Result<PrivateKey, crypto::Error> {
        engine.get_shared_privkey(key_type)
    }

    fn as_bytes(privkey: &PrivateKey) -> Vec<u8> {
        privkey.as_bytes().into()
    }
}

pub fn private_spend_from_seed<T: AsRef<[u8]>>(seed: T) -> Result<PrivateKey, crypto::Error> {
    let mut bytes = Vec::from(b"farcaster_priv_spend".as_ref());
    bytes.extend_from_slice(&seed.as_ref());

    let mut key = Hash::hash(&bytes).to_fixed_bytes();
    key[31] &= 0b0000_1111; // Chop off bits that might be greater than the curve modulus

    PrivateKey::from_slice(&key).map_err(|e| crypto::Error::new(e))
}

#[derive(Clone, Debug)]
pub struct Wallet {
    seed: [u8; 32],
}

impl Wallet {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    pub fn get_privkey(&self, key_type: AccordantKey) -> Result<PrivateKey, crypto::Error> {
        match key_type {
            AccordantKey::Spend => private_spend_from_seed(&self.seed),
        }
    }

    pub fn get_shared_privkey(
        &self,
        key_type: SharedPrivateKey,
    ) -> Result<PrivateKey, crypto::Error> {
        match key_type {
            SharedPrivateKey::View => {
                let mut bytes = Vec::from(b"farcaster_priv_view".as_ref());
                bytes.extend_from_slice(&self.seed.as_ref());
                Ok(Hash::hash(&bytes).as_scalar())
            }
        }
    }

    pub fn get_pubkey(&self, key_type: AccordantKey) -> Result<PublicKey, crypto::Error> {
        Ok(PublicKey::from_private_key(&self.get_privkey(key_type)?))
    }
}

#[async_trait]
impl FromSeed<Acc> for Monero {
    type Engine = Wallet;

    async fn get_pubkey(
        engine: &Wallet,
        key_type: AccordantKey,
    ) -> Result<PublicKey, crypto::Error> {
        engine.get_pubkey(key_type)
    }
}
