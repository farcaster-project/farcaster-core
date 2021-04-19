//! Defines and implements all the traits for Bitcoin

use bitcoin::hash_types::PubkeyHash;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::Signature;
use bitcoin::util::amount;
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::Network;
use strict_encoding::{StrictDecode, StrictEncode};

use farcaster_core::blockchain::{self, Asset, Onchain, Timelock, Transactions};
use farcaster_core::consensus::{self, Decodable, Encodable};
use farcaster_core::crypto::{ArbitratingKey, Commitment, FromSeed, Keys, Signatures};
use farcaster_core::role::{Arb, Arbitrating};

use transaction::{Buy, Cancel, Funding, Lock, Punish, Refund, Tx};

use std::fmt::Debug;
use std::io;
use std::str::FromStr;

pub mod fee;
pub mod transaction;

#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct Bitcoin;

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

impl FromStr for Amount {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = s
            .parse::<u64>()
            .map_err(|_| consensus::Error::ParseFailed("Failed to parse amount"))?;
        Ok(Self(amount::Amount::from_sat(x)))
    }
}

/// Bitcoin amount wrapper
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, StrictDecode, StrictEncode)]
pub struct Amount(amount::Amount);

impl Amount {
    pub fn as_sat(&self) -> u64 {
        self.0.as_sat()
    }

    pub fn from_sat(sat: u64) -> Self {
        Self(amount::Amount::from_sat(sat))
    }

    pub fn checked_mul(&self, other: u64) -> Option<Self> {
        Some(Self(self.0.checked_mul(other)?))
    }

    pub fn checked_sub(&self, other: Self) -> Option<Self> {
        Some(Self(self.0.checked_sub(other.0)?))
    }
}

impl Encodable for Amount {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        bitcoin::consensus::encode::Encodable::consensus_encode(&self.as_sat(), writer)
    }
}

impl Decodable for Amount {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let sats: u64 = bitcoin::consensus::encode::Decodable::consensus_decode(d)
            .map_err(|_| consensus::Error::ParseFailed("Bitcoin amount parsing failed"))?;
        Ok(Amount::from_sat(sats))
    }
}

impl blockchain::Address for Bitcoin {
    /// Defines the address format for the arbitrating blockchain
    type Address = Address;
}

impl Timelock for Bitcoin {
    /// Defines the type of timelock used for the arbitrating transactions
    type Timelock = CSVTimelock;
}

impl Arbitrating for Bitcoin {}

#[derive(Debug, Clone, StrictDecode, StrictEncode)]
pub struct Address(pub bitcoin::Address);

impl From<bitcoin::Address> for Address {
    fn from(address: bitcoin::Address) -> Self {
        Self(address)
    }
}

impl AsRef<bitcoin::Address> for Address {
    fn as_ref(&self) -> &bitcoin::Address {
        &self.0
    }
}

impl Encodable for Address {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        bitcoin::consensus::encode::Encodable::consensus_encode(&self.0.to_string(), writer)
    }
}

impl Decodable for Address {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let bytes: String = bitcoin::consensus::encode::Decodable::consensus_decode(d)
            .map_err(|_| consensus::Error::ParseFailed("Bitcoin address parsing failed"))?;
        let add: bitcoin::Address = FromStr::from_str(&bytes)
            .map_err(|_| consensus::Error::ParseFailed("Bitcoin address parsing failed"))?;
        Ok(Address(add))
    }
}

impl FromStr for CSVTimelock {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let x = s
            .parse::<u32>()
            .map_err(|_| consensus::Error::ParseFailed("Failed parsing CSV timelock"))?;
        Ok(CSVTimelock(x))
    }
}

#[derive(PartialEq, Eq, PartialOrd, Clone, Debug, StrictDecode, StrictEncode, Copy)]
#[strict_encoding_crate(strict_encoding)]
pub struct CSVTimelock(u32);

impl CSVTimelock {
    pub fn new(timelock: u32) -> Self {
        Self(timelock)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl Encodable for CSVTimelock {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        bitcoin::consensus::encode::Encodable::consensus_encode(&self.0, writer)
    }
}

impl Decodable for CSVTimelock {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let timelock: u32 = bitcoin::consensus::encode::Decodable::consensus_decode(d)
            .map_err(|_| consensus::Error::ParseFailed("Bitcoin u32 timelock parsing failed"))?;
        Ok(CSVTimelock(timelock))
    }
}

impl Onchain for Bitcoin {
    /// Defines the transaction format used to transfer partial transaction between participant for
    /// the arbitrating blockchain
    type PartialTransaction = PartiallySignedTransaction;

    /// Defines the finalized transaction format for the arbitrating blockchain
    type Transaction = bitcoin::blockdata::transaction::Transaction;
}

impl Transactions for Bitcoin {
    type Metadata = transaction::MetadataOutput;

    type Error = transaction::Error;

    type Funding = Funding;
    type Lock = Tx<Lock>;
    type Buy = Tx<Buy>;
    type Cancel = Tx<Cancel>;
    type Refund = Tx<Refund>;
    type Punish = Tx<Punish>;
}

#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
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

    fn as_bytes(pubkey: &PublicKey) -> Vec<u8> {
        pubkey.to_bytes()
    }
}

impl Commitment for Bitcoin {
    type Commitment = PubkeyHash;

    fn commit_to<T: AsRef<[u8]>>(value: T) -> PubkeyHash {
        PubkeyHash::hash(value.as_ref())
    }
}

impl Signatures for Bitcoin {
    type Signature = Signature;
    type AdaptorSignature = ECDSAAdaptorSig;
}

impl FromSeed<Arb> for Bitcoin {
    type Seed = [u8; 32];

    fn get_pubkey(seed: &[u8; 32], key_type: ArbitratingKey) -> PublicKey {
        let secp = Secp256k1::new();
        let master_key = ExtendedPrivKey::new_master(Network::Bitcoin, seed.as_ref()).unwrap();
        let key = match key_type {
            ArbitratingKey::Fund => master_key
                .derive_priv(&secp, &DerivationPath::from_str("m/0/1/1").unwrap())
                .unwrap(),
            ArbitratingKey::Buy => master_key
                .derive_priv(&secp, &DerivationPath::from_str("m/0/1/2").unwrap())
                .unwrap(),
            ArbitratingKey::Cancel => master_key
                .derive_priv(&secp, &DerivationPath::from_str("m/0/1/3").unwrap())
                .unwrap(),
            ArbitratingKey::Refund => master_key
                .derive_priv(&secp, &DerivationPath::from_str("m/0/1/4").unwrap())
                .unwrap(),
            ArbitratingKey::Punish => master_key
                .derive_priv(&secp, &DerivationPath::from_str("m/0/1/5").unwrap())
                .unwrap(),
        };
        key.private_key.public_key(&secp)
    }
}
