//! Defines and implements all the traits for Monero

use crate::blockchain::{self, Asset};
use crate::consensus::{self, AsCanonicalBytes, Decodable, Encodable};
use crate::crypto::{Keys, SharedKeyId, SharedPrivateKeys};
use crate::role::Accordant;

use monero::util::key::{PrivateKey, PublicKey};
use monero::Address;
use monero::Amount;

use std::fmt::{self, Debug, Display, Formatter};
use std::io;

pub mod tasks;

pub const SHARED_VIEW_KEY_ID: u16 = 0x01;

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct Monero;

impl Accordant for Monero {}

impl std::str::FromStr for Monero {
    type Err = crate::consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Monero" => Ok(Monero),
            _ => Err(crate::consensus::Error::UnknownType),
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
    type AssetUnit = Amount;

    fn from_u32(bytes: u32) -> Option<Self> {
        match bytes {
            0x80000080 => Some(Self),
            _ => None,
        }
    }

    fn to_u32(&self) -> u32 {
        0x80000080
    }
}

impl Encodable for Amount {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        monero::consensus::encode::Encodable::consensus_encode(&self.as_pico(), writer)
    }
}

impl Decodable for Amount {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let pico: u64 = monero::consensus::encode::Decodable::consensus_decode(d)
            .map_err(|_| consensus::Error::ParseFailed("Monero amount parsing failed"))?;
        Ok(Amount::from_pico(pico))
    }
}

impl blockchain::Address for Monero {
    type Address = Address;
}

impl Encodable for Address {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        monero::consensus::encode::Encodable::consensus_encode(&self.as_bytes(), writer)
    }
}

impl Decodable for Address {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let bytes: Vec<u8> = monero::consensus::encode::Decodable::consensus_decode(d)
            .map_err(|_| consensus::Error::ParseFailed("Parsing failed"))?;
        Ok(Address::from_bytes(&bytes[..])
            .map_err(|_| consensus::Error::ParseFailed("Parsing failed"))?)
    }
}

impl Keys for Monero {
    /// Private key type for the blockchain
    type PrivateKey = PrivateKey;

    /// Public key type for the blockchain
    type PublicKey = PublicKey;

    fn extra_keys() -> Vec<u16> {
        // No extra key
        vec![]
    }
}

impl AsCanonicalBytes for PrivateKey {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.to_bytes().into()
    }
}

impl AsCanonicalBytes for PublicKey {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.as_bytes().into()
    }
}

impl SharedPrivateKeys for Monero {
    type SharedPrivateKey = PrivateKey;

    fn shared_keys() -> Vec<SharedKeyId> {
        // Share one key: the private view key
        vec![SharedKeyId::new(SHARED_VIEW_KEY_ID)]
    }
}
