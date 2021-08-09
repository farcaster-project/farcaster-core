//! Implementation for the Bitcoin blockchain as an arbitrating blockchain in a swap, with multiple
//! strategies (ECDSA, Taproot, Taproot+MuSig2).

use std::fmt::Debug;
use std::marker::PhantomData;

use bitcoin::secp256k1::Signature;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::Address;
use bitcoin::Amount;

use crate::blockchain::{self, Asset, Onchain, Timelock};
use crate::consensus::{self, CanonicalBytes};

pub(crate) mod address;
pub(crate) mod amount;
pub mod fee;
#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
pub mod segwitv0;
pub mod tasks;
pub mod timelock;
pub mod transaction;

/// Bitcoin blockchain using SegWit version 0 transaction outputs and ECDSA cryptography. This type
/// is experimental because it uses ECDSA Adaptor Signatures that are not ready for production.
#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
pub type BitcoinSegwitV0 = Bitcoin<segwitv0::SegwitV0>;

/// Helper type enumerating over all Bitcoin inner variants available.
#[non_exhaustive]
pub enum Btc {
    #[cfg(feature = "experimental")]
    #[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
    SegwitV0(BitcoinSegwitV0),
}

/// Variations of a Bitcoin implementation. Strategy allows different Bitcoin implementations based
/// on, e.g., the SegWit version such as [`SegwitV0`][segwitv0::SegwitV0].
pub trait Strategy: Clone + Copy + Debug {}

/// The generic blockchain implementation of Bitcoin. [`Bitcoin`] takes a generic parameter
/// [`Strategy`] to allow different definition of Bitcoin such as different SegWit version (v0, v1)
/// or even different type of cryptography (v1 with on-chain scripts or v1 with MuSig2 off-chain
/// multisigs).
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct Bitcoin<S: Strategy> {
    _e: PhantomData<S>,
}

impl<S: Strategy> Bitcoin<S> {
    pub fn new() -> Self {
        Self { _e: PhantomData }
    }
}

impl<S: Strategy> Asset for Bitcoin<S> {
    /// Type for the traded asset unit
    type AssetUnit = Amount;

    fn from_u32(bytes: u32) -> Option<Self> {
        match bytes {
            0x80000000 => Some(Self::new()),
            _ => None,
        }
    }

    fn to_u32(&self) -> u32 {
        0x80000000
    }
}

impl<S: Strategy> blockchain::Address for Bitcoin<S> {
    /// Defines the address format for the arbitrating blockchain
    type Address = Address;
}

impl<S: Strategy> Timelock for Bitcoin<S> {
    /// Defines the type of timelock used for the arbitrating transactions
    type Timelock = timelock::CSVTimelock;
}

impl<S: Strategy> Onchain for Bitcoin<S> {
    /// Defines the transaction format used to transfer partial transaction between participant for
    /// the arbitrating blockchain
    type PartialTransaction = PartiallySignedTransaction;

    /// Defines the finalized transaction format for the arbitrating blockchain
    type Transaction = bitcoin::Transaction;
}

impl CanonicalBytes for PrivateKey {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        let key =
            bitcoin::secp256k1::SecretKey::from_slice(bytes).map_err(consensus::Error::new)?;
        Ok(PrivateKey {
            compressed: true,
            network: bitcoin::Network::Bitcoin,
            key,
        })
    }
}

impl CanonicalBytes for PublicKey {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        PublicKey::from_slice(bytes).map_err(consensus::Error::new)
    }
}

impl CanonicalBytes for Signature {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.serialize_compact().into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        Signature::from_compact(bytes).map_err(consensus::Error::new)
    }
}
