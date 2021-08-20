//! Implementation of the Monero blockchain as an accordant blockchain in a swap. This
//! implementation should work in pair with any other arbitrating implementation, like Bitcoin.

use crate::blockchain::{self, Asset};
use crate::consensus::{self, CanonicalBytes};
use crate::crypto::{Keys, SharedKeyId, SharedPrivateKeys};
use crate::role::Accordant;

use monero::util::key::{PrivateKey, PublicKey};
use monero::Address;
use monero::Amount;

use std::fmt::{self, Debug, Display, Formatter};

pub mod tasks;

/// The identifier for the only shared private key on the Monero side: the secret view key.
pub const SHARED_VIEW_KEY_ID: u16 = 0x01;

/// The implementation of Monero with all the traits necessary to comply with [`Accordant`]
/// blockchain role.
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

impl CanonicalBytes for Amount {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        monero::consensus::encode::serialize(&self.as_pico())
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        Ok(Amount::from_pico(
            monero::consensus::encode::deserialize(bytes).map_err(consensus::Error::new)?,
        ))
    }
}

impl blockchain::Address for Monero {
    type Address = Address;
}

impl CanonicalBytes for Address {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.as_bytes()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        Address::from_bytes(bytes).map_err(consensus::Error::new)
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

impl CanonicalBytes for PrivateKey {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.to_bytes().into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        PrivateKey::from_slice(bytes).map_err(consensus::Error::new)
    }
}

impl CanonicalBytes for PublicKey {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.as_bytes().into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        PublicKey::from_slice(bytes).map_err(consensus::Error::new)
    }
}

impl SharedPrivateKeys for Monero {
    type SharedPrivateKey = PrivateKey;

    fn shared_keys() -> Vec<SharedKeyId> {
        // Share one key: the private view key
        vec![SharedKeyId::new(SHARED_VIEW_KEY_ID)]
    }
}
