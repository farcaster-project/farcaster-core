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

//! Farcaster core library aims to implement in Rust the core principles described in Farcaster
//! [RFCs](https://github.com/farcaster-project/RFCs):
//!
//! - Swap deals: data needed to start a swap with a counter-party
//! - Swap roles and trade roles: who does what in the protocol
//! - Transaction templates implementing on-chain behaviours
//! - Signature and cryptographic utilities
//!   - ECDSA adaptor signatures
//!   - Cross-group discrete logarithm proof system
//!   - Schnorr adaptor signature [work in progress]
//!
//! ## Core framework
//! This library is twofold: providing a flexible framework to add specific blockchain support and
//! implementing these specific blockchains. The framework is accessible in all modules at the root
//! of the crate. The blockchains support are added under the the following modules:
//!
//! - `bitcoin`: support for Bitcoin, implementation of the `Arbitrating` blockchain role.
//! - `monero`: support for Monero, implementation of the `Accordant` blockchain role.
//! - `swap/btcxmr`: definition of a swap between `bitcoin` and `monero` implementations.
//!
//! ### Adding blockchain support
//! To add a blockchain implementation you must implements the `Aribtrating` or `Accordant` role
//! requirements on your blockchain. That depends on its blockchain on-chain features, see
//! [RFCs](https://github.com/farcaster-project/RFCs) for more details.
//!
//! The protocol is executed with `protocol::Alice` and `protocol::Bob` structures, each implement
//! a list of generic functions that allow performing one step in the protocol execution. Adding
//! support for a chain means having the correct types to run those functions.
//!
//! For an arbitrating implementation on-chain transactions are required, the trait `Transactions`
//! allow defining the set of transaction to build and use during the swap execution.
//!
//! ### Features
//! As default the `experimental` feature is enable.
//!
//! - **experimental**: enable experimental cryptography, i.e. not battle tested nor peer reviewed,
//! use it at your own risks.
//! - **taproot**: enable support for Bitcoin Taproot on-chain scripts as the arbitrating engine
//! method.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "nightly", feature(stmt_expr_attributes))]
// Coding conventions
#![forbid(unsafe_code)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(unused_mut)]
//#![deny(missing_docs)]

#[macro_use]
extern crate amplify;

#[macro_use]
extern crate serde;

#[macro_use]
extern crate clap;

use std::io;
use std::str::FromStr;

use crate::consensus::{Decodable, Encodable};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[macro_use]
pub mod consensus;

pub mod bitcoin;
pub mod blockchain;
pub mod crypto;
pub(crate) mod hash;
pub mod monero;
pub mod protocol;
pub mod role;
pub mod script;
pub mod swap;
pub mod trade;
pub mod transaction;

/// A list of possible errors when performing a cross-chain atomic swap with the **Farcaster**
/// software stack. Each error can have multiple level down to the blockchain implementation.
#[derive(Error, Debug)]
pub enum Error {
    /// A consensus error during encoding/decoding operation or data type missmatch.
    #[error("Consensus error: {0}")]
    Consensus(#[from] consensus::Error),
    /// A cryptographic error during key manipulation, signatures, proofs, or commitments
    /// generation and validation.
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] crypto::Error),
    /// A fee error during application and validation of a fee strategy on arbitrating
    /// transactions.
    #[error("Fee Strategy error: {0}")]
    FeeStrategy(#[from] blockchain::FeeStrategyError),
    /// An arbitrating transaction error.
    #[error("Transaction error: {0}")]
    Transaction(#[from] transaction::Error),
    /// A trade error.
    #[error("Trade error: {0}")]
    Trade(#[from] trade::Error),
}

/// Result of an high level computation such as in Alice and Bob roles executing the protocol,
/// wraps the crate level [`enum@Error`] type.
pub type Res<T> = Result<T, Error>;

/// A unique identifier used to identify trades and swaps.
///
/// This is a wrapper against `uuid::Uuid` with `StrictEncode` and `StrictDecode` implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, Serialize, Deserialize)]
#[display(inner)]
pub struct Uuid(uuid::Uuid);

impl Uuid {
    /// Creates a new uuid for trades and swaps.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// Creates a new random uuid, same as `Self::new()`.
    pub fn random() -> Self {
        Self::new()
    }
}

impl Default for Uuid {
    fn default() -> Self {
        Self::new()
    }
}

impl From<uuid::Uuid> for Uuid {
    fn from(u: uuid::Uuid) -> Self {
        Self(u)
    }
}

impl FromStr for Uuid {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(uuid::Uuid::from_str(s)?))
    }
}

impl AsRef<uuid::Uuid> for Uuid {
    fn as_ref(&self) -> &uuid::Uuid {
        &self.0
    }
}

impl Encodable for Uuid {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        self.0.to_bytes_le().consensus_encode(s)
    }
}

impl Decodable for Uuid {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self(uuid::Uuid::from_bytes_le(
            Decodable::consensus_decode(d)?,
        )))
    }
}

impl strict_encoding::StrictEncode for Uuid {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        self.as_ref().to_bytes_le().strict_encode(&mut e)
    }
}

impl strict_encoding::StrictDecode for Uuid {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Ok(Self(uuid::Uuid::from_bytes_le(<[u8; 16]>::strict_decode(
            &mut d,
        )?)))
    }
}

#[cfg(test)]
mod tests {
    use super::Uuid;
    use uuid::uuid;

    #[test]
    fn serialize_swapid_in_yaml() {
        let id: Uuid = uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8").into();
        let s = serde_yaml::to_string(&id).expect("Encode swap id in yaml");
        assert_eq!("---\n67e55044-10b1-426f-9247-bb680e5fe0c8\n", s);
    }

    #[test]
    fn deserialize_swapid_from_yaml() {
        let s = "---\n67e55044-10b1-426f-9247-bb680e5fe0c8\n";
        let id: Uuid = serde_yaml::from_str(&s).expect("Decode uuid from yaml");
        assert_eq!(id, uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8").into(),);
    }
}
