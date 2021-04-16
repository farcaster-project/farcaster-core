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

#[derive(Error, Debug)]
pub enum Error {
    #[error("Consensus error: {0}")]
    Consensus(#[from] consensus::Error),
}
