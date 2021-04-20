//! Farcaster Core library

use thiserror::Error;

#[macro_use]
pub mod consensus;

pub mod blockchain;
pub mod bundle;
pub mod crypto;
pub mod datum;
pub mod instruction;
pub mod negotiation;
pub mod protocol_message;
pub mod role;
pub mod script;
pub mod swap;
pub mod transaction;
pub mod version;

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
}
