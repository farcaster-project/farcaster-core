//! Defines and implements all the traits for Bitcoin
use std::convert::TryFrom;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::str::FromStr;

use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::secp256k1::Signature;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::Address;
use bitcoin::Amount;

use crate::blockchain::{self, Asset, Onchain, Timelock, Transactions};
use crate::consensus::{self, CanonicalBytes};
use crate::crypto::{Keys, SharedKeyId, SharedPrivateKeys, Signatures};
use crate::role::Arbitrating;

use transaction::{Buy, Cancel, Funding, Lock, Punish, Refund, Tx};

pub(crate) mod address;
pub(crate) mod amount;
pub mod fee;
pub mod tasks;
pub mod timelock;
pub mod transaction;

/// Bitcoin blockchain using SegWit version 0 transaction and ECDSA cryptography.
pub type BitcoinSegwitV0 = Bitcoin<SegwitV0>;

/// Helper type enumerating over all Bitcoin variants.
#[non_exhaustive]
pub enum Btc {
    SegwitV0(BitcoinSegwitV0),
}

impl FromStr for Btc {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Bitcoin<SegwitV0>" => Ok(Self::SegwitV0(BitcoinSegwitV0::new())),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl From<BitcoinSegwitV0> for Btc {
    fn from(v: BitcoinSegwitV0) -> Self {
        Self::SegwitV0(v)
    }
}

/// Variations of a Bitcoin implementation. Engine allows different Bitcoin implementations based
/// on, e.g., the SegWit version such as [`SegwitV0`].
pub trait Engine: Clone + Copy + Debug {}

/// Implementation for SegWit version 0 transactions and ECDSA cryptography.
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct SegwitV0;

impl Engine for SegwitV0 {}

/// The generic blockchain implementation of Bitcoin. [`Bitcoin`] takes a generic parameter
/// [`Engine`] to allow different definition of Bitcoin such as different SegWit version (v0, v1)
/// or even different type of cryptography (v1 with on-chain scripts or v1 with MuSig2 off-chain
/// multisigs).
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct Bitcoin<E: Engine> {
    _e: PhantomData<E>,
}

impl<E: Engine> Bitcoin<E> {
    pub fn new() -> Self {
        Self { _e: PhantomData }
    }
}

impl Arbitrating for Bitcoin<SegwitV0> {}

impl TryFrom<Btc> for Bitcoin<SegwitV0> {
    type Error = consensus::Error;

    fn try_from(v: Btc) -> Result<Self, consensus::Error> {
        match v {
            Btc::SegwitV0(v) => Ok(v),
            //_ => Err(consensus::Error::TypeMismatch),
        }
    }
}

impl<E: Engine> Asset for Bitcoin<E> {
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

impl<E: Engine> blockchain::Address for Bitcoin<E> {
    /// Defines the address format for the arbitrating blockchain
    type Address = Address;
}

impl<E: Engine> Timelock for Bitcoin<E> {
    /// Defines the type of timelock used for the arbitrating transactions
    type Timelock = timelock::CSVTimelock;
}

impl<E: Engine> Onchain for Bitcoin<E> {
    /// Defines the transaction format used to transfer partial transaction between participant for
    /// the arbitrating blockchain
    type PartialTransaction = PartiallySignedTransaction;

    /// Defines the finalized transaction format for the arbitrating blockchain
    type Transaction = bitcoin::Transaction;
}

impl Transactions for Bitcoin<SegwitV0> {
    type Metadata = transaction::MetadataOutput;

    type Funding = Funding;
    type Lock = Tx<Lock>;
    type Buy = Tx<Buy>;
    type Cancel = Tx<Cancel>;
    type Refund = Tx<Refund>;
    type Punish = Tx<Punish>;
}

impl Keys for Bitcoin<SegwitV0> {
    /// Private key type for the blockchain
    type PrivateKey = PrivateKey;

    /// Public key type for the blockchain
    type PublicKey = PublicKey;

    fn extra_keys() -> Vec<u16> {
        // No extra key
        vec![]
    }
}

impl SharedPrivateKeys for Bitcoin<SegwitV0> {
    type SharedPrivateKey = PrivateKey;

    fn shared_keys() -> Vec<SharedKeyId> {
        // No shared key in Bitcoin, transparent ledger
        vec![]
    }
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

impl Signatures for Bitcoin<SegwitV0> {
    type Message = Sha256dHash;
    type Signature = Signature;
    type AdaptorSignature = Signature;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn from_str_and_convertion() {
        let parse = Btc::from_str("Bitcoin<SegwitV0>");
        assert!(parse.is_ok());
        let parse = parse.unwrap();
        let into: Result<BitcoinSegwitV0, _> = parse.try_into();
        assert!(into.is_ok());
    }
}
