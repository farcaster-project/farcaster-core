//! Defines and implements all the traits for Bitcoin

use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::secp256k1::Signature;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::Address;
use bitcoin::Amount;

use crate::blockchain::{self, Asset, Onchain, Timelock, Transactions};
use crate::consensus::{self, AsCanonicalBytes};
use crate::crypto::{Keys, SharedKeyId, SharedPrivateKeys, Signatures};
use crate::role::Arbitrating;

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
    type AssetUnit = Amount;

    fn from_u32(bytes: u32) -> Option<Self> {
        match bytes {
            0x80000000 => Some(Self),
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
    type AdaptorSignature = Signature;
}
