//!  ⚠️ **This library is a 🚧 work in progress 🚧 and does not implement everything yet, nor is
//!  suitable for production use.**
//!
//! Farcaster core library aims to implement in Rust:
//!
//! - Swap offers
//! - Swap roles and trade roles
//! - Transaction templates implementing on-chain behaviours
//! - Messages exchanged between
//!   [farcaster-node](https://github.com/farcaster-project/farcaster-node)'s microservices
//! - Tasks and blockchain events used by syncers
//! - Signature and cryptographic utilities
//!   - `experimental` ECDSA adaptor signatures (with `ecdsa_fun`)
//!   - Cross-group discrete logarithm proof system
//!   - Schnorr adaptor signature
//!
//! ## Core framework
//! This library is twofold: providing a flexible framework to add specific blockchain support and
//! implementing these specific blockchains. The framework is accessible in all modules at the root
//! of the crate. The blockchains support are added under the the following modules:
//!
//! - `bitcoin`: support for Bitcoin, implementation of the `Arbitrating` role.
//! - `monero`: support for Monero, implementation of the `Accordant` role.
//! - `swap/btcxmr`: definition of a swap between `bitcoin` and `monero` implementations.
//!
//! ### Adding blockchain support
//! To add a blockchain implementation you must implements `Aribtrating` or `Accordant` trait on
//! your blockchain definition, the trait implemented depends on its blockchain on-chain features,
//! see [RFCs](https://github.com/farcaster-project/RFCs) for more details.
//!
//! The implementation of blockchain roles is void but requires a list of other traits (see
//! `role`). Some traits only associate types, some carry more logic such as `Keys` in `crypto`
//! module that defines the type of keys (public and private) and the number of extra keys needed
//! during the swap. This is useful when off-chain cryptographic protocols such as MuSig2 is used
//! in the implementation and requires extra keys, e.g. nonces.
//!
//! For an arbitrating implementation transactions are required through `Onchain` and
//! `Transactions` traits, former associate types for partial and final transaction and latter give
//! concrete implementation for every type of transaction.
//!
//! ### Features
//! As default the `experimental` feature is enable.
//!
//! - **experimental**: enable experimental cryptography, i.e. not battle tested nor peer reviewed
//! and not intended for production use.
//! - **taproot**: enable support for Bitcoin Taproot on-chain scripts as the arbitrating engine
//! method.

#![cfg_attr(docsrs, feature(doc_cfg))]
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

use thiserror::Error;

#[macro_use]
pub mod consensus;

pub mod bitcoin;
pub mod blockchain;
pub mod bundle;
pub mod crypto;
pub(crate) mod hash;
pub mod instruction;
pub mod monero;
pub mod negotiation;
pub mod protocol;
pub mod role;
pub mod script;
pub mod swap;
pub mod syncer;
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
    /// A negotiation error.
    #[error("Negotiation error: {0}")]
    Negotiation(#[from] negotiation::Error),
    /// A syncer task or event error.
    #[error("Syncer error: {0}")]
    Syncer(#[from] syncer::Error),
}

/// Result of an high level computation such as in Alice and Bob roles executing the protocol,
/// wraps the crate level [`enum@Error`] type.
pub type Res<T> = Result<T, Error>;
