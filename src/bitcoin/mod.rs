//! Implementation for the Bitcoin blockchain as an arbitrating blockchain in a swap, with multiple
//! strategies (ECDSA, Taproot, Taproot+MuSig2).

use std::fmt::Debug;
use std::marker::PhantomData;

use bitcoin::secp256k1::{
    key::{PublicKey, SecretKey},
    Signature,
};
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
    /// Create a new Bitcoin for the defined strategy.
    pub fn new() -> Self {
        Self { _e: PhantomData }
    }
}

impl<S: Strategy> Default for Bitcoin<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Strategy> Asset for Bitcoin<S> {
    /// Type for quantifying the traded asset.
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
    /// Defines the address format used in Bitcoin.
    type Address = Address;
}

impl<S: Strategy> Timelock for Bitcoin<S> {
    /// Defines the type of timelock used in Bitcoin.
    type Timelock = timelock::CSVTimelock;
}

impl<S: Strategy> Onchain for Bitcoin<S> {
    /// Defines the transaction format used to transfer partial transaction between participants in
    /// Bitcoin.
    type PartialTransaction = PartiallySignedTransaction;

    /// Defines the finalized transaction format for Bitcoin used by the syncers.
    type Transaction = bitcoin::Transaction;
}

impl CanonicalBytes for SecretKey {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        (&self.as_ref()[..]).into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        SecretKey::from_slice(bytes).map_err(consensus::Error::new)
    }
}

impl CanonicalBytes for PublicKey {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.serialize().as_ref().into()
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
