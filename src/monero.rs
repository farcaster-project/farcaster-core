//! Implementation of the Monero blockchain as an accordant blockchain in a swap. This
//! implementation should work in pair with any other arbitrating implementation, like Bitcoin.

use crate::blockchain::{self, Asset, Network};
use crate::consensus::{self, CanonicalBytes};
use crate::crypto::{self, AccordantKeys, Keys, SharedKeyId, SharedSecretKeys, SwapAccordantKeys};
use crate::role::Accordant;

use monero::util::key::{PrivateKey, PublicKey};
use monero::Address;
use monero::Amount;

use std::fmt::{self, Debug};

pub mod tasks;

/// The identifier for the only shared private key on the Monero side: the secret view key.
pub const SHARED_VIEW_KEY_ID: u16 = 0x01;

/// The implementation of Monero with all the traits necessary to comply with [`Accordant`]
/// blockchain role.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct Monero;

impl Accordant for Monero {
    fn derive_lock_address(
        network: Network,
        keys: SwapAccordantKeys<Self>,
    ) -> Result<Address, crypto::Error> {
        let SwapAccordantKeys {
            alice:
                AccordantKeys {
                    spend_key: alice_spend_key,
                    shared_keys: alice_shared_keys,
                    ..
                },
            bob:
                AccordantKeys {
                    spend_key: bob_spend_key,
                    shared_keys: bob_shared_keys,
                    ..
                },
        } = keys;

        let alice_tagged_view_secretkey = alice_shared_keys
            .iter()
            .find(|tagged_key| *tagged_key.tag() == SharedKeyId::new(SHARED_VIEW_KEY_ID))
            .ok_or(crypto::Error::MissingKey)?;
        let bob_tagged_view_secretkey = bob_shared_keys
            .iter()
            .find(|tagged_key| *tagged_key.tag() == SharedKeyId::new(SHARED_VIEW_KEY_ID))
            .ok_or(crypto::Error::MissingKey)?;

        let public_spend = alice_spend_key + bob_spend_key;
        let secret_view = alice_tagged_view_secretkey.elem() + bob_tagged_view_secretkey.elem();
        let public_view = PublicKey::from_private_key(&secret_view);

        Ok(Address::standard(network.into(), public_spend, public_view))
    }
}

impl From<Network> for monero::Network {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => monero::Network::Mainnet,
            Network::Testnet => monero::Network::Stagenet,
            Network::Local => monero::Network::Mainnet,
        }
    }
}

impl std::str::FromStr for Monero {
    type Err = crate::consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Monero" | "monero" | "xmr" => Ok(Monero),
            _ => Err(crate::consensus::Error::UnknownType),
        }
    }
}

impl fmt::Display for Monero {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Monero")
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
    type SecretKey = PrivateKey;
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

impl SharedSecretKeys for Monero {
    type SharedSecretKey = PrivateKey;

    fn shared_keys() -> Vec<SharedKeyId> {
        // Share one key: the private view key
        vec![SharedKeyId::new(SHARED_VIEW_KEY_ID)]
    }
}
