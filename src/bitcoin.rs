//! Implementation for the Bitcoin blockchain as an arbitrating blockchain in a swap, with multiple
//! strategies (ECDSA, Taproot, Taproot+MuSig2).

use std::fmt::Debug;
use std::marker::PhantomData;

use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::Address;
use bitcoin::Amount;

use crate::blockchain::{self, Asset, Onchain, Timelock};

pub(crate) mod address;
pub(crate) mod amount;
pub mod fee;
#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
pub mod segwitv0;
#[cfg(all(feature = "experimental", feature = "taproot"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "experimental", feature = "taproot"))))]
pub mod taproot;
pub mod tasks;
pub mod timelock;
pub mod transaction;

/// Bitcoin blockchain using SegWit version 0 transaction outputs and ECDSA cryptography. This type
/// is experimental because it uses ECDSA Adaptor Signatures that are not ready for production.
#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
pub type BitcoinSegwitV0 = Bitcoin<segwitv0::SegwitV0>;

/// Bitcoin blockchain using SegWit version 1 transaction outputs and Schnorr cryptography. This
/// type is experimental because its cryptography for Adaptor Signatures is not ready for
/// production and battle tested.
#[cfg(all(feature = "experimental", feature = "taproot"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "experimental", feature = "taproot"))))]
pub type BitcoinTaproot = Bitcoin<taproot::Taproot>;

/// Helper type enumerating over all Bitcoin inner variants available.
#[non_exhaustive]
pub enum Btc {
    #[cfg(feature = "experimental")]
    #[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
    SegwitV0(BitcoinSegwitV0),
    #[cfg(all(feature = "experimental", feature = "taproot"))]
    #[cfg_attr(docsrs, doc(cfg(all(feature = "experimental", feature = "taproot"))))]
    Taproot(BitcoinTaproot),
}

/// Variations of a Bitcoin implementation. Strategy allows different Bitcoin implementations based
/// on, e.g., the SegWit version such as [`SegwitV0`][segwitv0::SegwitV0] or
/// [`Taproot`][taproot::Taproot].
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
    type Address = Address;
}

impl<S: Strategy> Timelock for Bitcoin<S> {
    type Timelock = timelock::CSVTimelock;
}

impl<S: Strategy> Onchain for Bitcoin<S> {
    type PartialTransaction = PartiallySignedTransaction;
    type Transaction = bitcoin::Transaction;
}
