// Copyright 2021-2022 Farcaster Devs
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

//! Implementation for the Bitcoin blockchain as an arbitrating blockchain in a swap, with multiple
//! strategies (ECDSA, Taproot, Taproot+MuSig2).

use std::fmt::Debug;
use std::io;
use std::marker::PhantomData;

use ecdsa_fun::adaptor::EncryptedSignature;

use crate::blockchain::Network;
use crate::consensus::{self, CanonicalBytes, Decodable, Encodable};

pub(crate) mod address;
pub(crate) mod amount;
pub mod fee;
#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
pub mod segwitv0;
#[cfg(all(feature = "experimental", feature = "taproot"))]
#[cfg_attr(docsrs, doc(cfg(all(feature = "experimental", feature = "taproot"))))]
pub mod taproot;
pub mod timelock;
pub mod transaction;

/// Bitcoin blockchain using SegWit version 0 transaction outputs and ECDSA cryptography. This type
/// is experimental because it uses ECDSA Adaptor Signatures that are not ready for production.
#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
pub type BitcoinSegwitV0 = Bitcoin<segwitv0::SegwitV0>;

#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
impl Decodable for BitcoinSegwitV0 {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x80000000u32 => Ok(Self::new()),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
impl Encodable for BitcoinSegwitV0 {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        0x80000000u32.consensus_encode(writer)
    }
}

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

impl From<Network> for bitcoin::Network {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::Bitcoin,
            Network::Testnet => Self::Testnet,
            Network::Local => Self::Regtest,
        }
    }
}

impl From<bitcoin::Network> for Network {
    fn from(network: bitcoin::Network) -> Self {
        match network {
            bitcoin::Network::Bitcoin => Self::Mainnet,
            bitcoin::Network::Testnet => Self::Testnet,
            bitcoin::Network::Signet => Self::Testnet,
            bitcoin::Network::Regtest => Self::Local,
        }
    }
}

impl Encodable for EncryptedSignature {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        self.as_canonical_bytes().consensus_encode(writer)
    }
}

impl Decodable for EncryptedSignature {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Self::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())
    }
}
