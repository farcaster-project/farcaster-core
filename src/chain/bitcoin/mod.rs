//! Defines and implements all the traits for Bitcoin

use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::secp256k1::Signature;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::PartiallySignedTransaction;
use strict_encoding::{StrictDecode, StrictEncode};

use crate::blockchain::{self, Asset, Onchain, Timelock, Transactions};
use crate::consensus::{self, AsCanonicalBytes};
use crate::crypto::{Keys, SharedKeyId, SharedPrivateKeys, Signatures};
use crate::role::Arbitrating;

use address::Address;
use transaction::{Buy, Cancel, Funding, Lock, Punish, Refund, Tx};

use std::fmt::Debug;
use std::str::FromStr;

pub mod address;
pub mod amount;
pub mod fee;
pub mod tasks;
pub mod timelock;
pub mod transaction;

#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct Bitcoin;

impl Arbitrating for Bitcoin {}

impl FromStr for Bitcoin {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Bitcoin" => Ok(Self),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl Asset for Bitcoin {
    /// Type for the traded asset unit
    type AssetUnit = amount::Amount;

    /// Create a new Bitcoin blockchain
    fn new() -> Self {
        Bitcoin {}
    }

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

impl blockchain::Address for Bitcoin {
    /// Defines the address format for the arbitrating blockchain
    type Address = Address;
}

impl Timelock for Bitcoin {
    /// Defines the type of timelock used for the arbitrating transactions
    type Timelock = timelock::CSVTimelock;
}

impl Onchain for Bitcoin {
    /// Defines the transaction format used to transfer partial transaction between participant for
    /// the arbitrating blockchain
    type PartialTransaction = PartiallySignedTransaction;

    /// Defines the finalized transaction format for the arbitrating blockchain
    type Transaction = bitcoin::Transaction;
}

impl Transactions for Bitcoin {
    type Metadata = transaction::MetadataOutput;

    type Funding = Funding;
    type Lock = Tx<Lock>;
    type Buy = Tx<Buy>;
    type Cancel = Tx<Cancel>;
    type Refund = Tx<Refund>;
    type Punish = Tx<Punish>;
}

#[derive(Clone, Debug, StrictDecode, StrictEncode)]
pub struct ECDSAAdaptorSig {
    pub sig: Signature,
    pub point: PublicKey,
    pub dleq: PDLEQ,
}

/// Produces a zero-knowledge proof of knowledge of the same relation k between two pairs of
/// elements in the same group, i.e. `(G, R')` and `(T, R)`.
#[derive(Clone, Debug)]
pub struct PDLEQ;

impl StrictEncode for PDLEQ {
    fn strict_encode<E: std::io::Write>(&self, mut _e: E) -> Result<usize, strict_encoding::Error> {
        Ok(0)
    }
}

impl StrictDecode for PDLEQ {
    fn strict_decode<D: std::io::Read>(mut _d: D) -> Result<Self, strict_encoding::Error> {
        Ok(Self)
    }
}

impl Keys for Bitcoin {
    /// Private key type for the blockchain
    type PrivateKey = PrivateKey;

    /// Public key type for the blockchain
    type PublicKey = PublicKey;

    fn extra_keys() -> Vec<u16> {
        // No extra key
        vec![]
    }
}

impl SharedPrivateKeys for Bitcoin {
    type SharedPrivateKey = PrivateKey;

    fn shared_keys() -> Vec<SharedKeyId> {
        // No shared key in Bitcoin, transparent ledger
        vec![]
    }
}

impl AsCanonicalBytes for PrivateKey {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl AsCanonicalBytes for PublicKey {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl Signatures for Bitcoin {
    type Message = Sha256dHash;
    type Signature = Signature;
    type AdaptorSignature = ECDSAAdaptorSig;
}
