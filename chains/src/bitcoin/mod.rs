//! Defines and implements all the traits for Bitcoin

use bitcoin::hashes::sha256d::Hash as Sha256dHash;
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
use farcaster_core::crypto::{self, ArbitratingKey, FromSeed, Keys, Signatures};
use farcaster_core::role::{Arb, Arbitrating};

use transaction::{Buy, Cancel, Funding, Lock, Punish, Refund, Tx};

use std::fmt::Debug;
use std::io;
use std::str;
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
    type Address = bitcoin::Address;

    fn as_bytes(data: &bitcoin::Address) -> Result<Vec<u8>, io::Error> {
        Ok(data.to_string().into())
    }

    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<bitcoin::Address, consensus::Error> {
        let add: bitcoin::Address =
            FromStr::from_str(str::from_utf8(bytes.as_ref()).map_err(|_| {
                consensus::Error::ParseFailed("Invalid UTF-8 encoded Bitcoin address")
            })?)
            .map_err(|_| consensus::Error::ParseFailed("Bitcoin address parsing failed"))?;
        Ok(add)
    }
}

impl Timelock for Bitcoin {
    /// Defines the type of timelock used for the arbitrating transactions
    type Timelock = CSVTimelock;

    fn as_bytes(data: &CSVTimelock) -> Result<Vec<u8>, io::Error> {
        Ok(bitcoin::consensus::encode::serialize(&data.0))
    }

    fn from_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<CSVTimelock, consensus::Error> {
        let timelock: u32 = bitcoin::consensus::encode::deserialize(bytes.as_ref())
            .map_err(|_| consensus::Error::ParseFailed("Bitcoin u32 timelock parsing failed"))?;
        Ok(CSVTimelock(timelock))
    }
}

impl Arbitrating for Bitcoin {}

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
pub struct CSVTimelock(u32);

impl CSVTimelock {
    pub fn new(timelock: u32) -> Self {
        Self(timelock)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
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

    fn as_bytes(pubkey: &PublicKey) -> Vec<u8> {
        pubkey.to_bytes()
    }
}

#[derive(Clone, Debug)]
pub struct Wallet {
    seed: [u8; 32],
}

impl Wallet {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }

    pub fn get_privkey(&self, key_type: ArbitratingKey) -> Result<PrivateKey, crypto::Error> {
        let secp = Secp256k1::new();
        let master_key = ExtendedPrivKey::new_master(Network::Bitcoin, self.seed.as_ref())
            .map_err(|e| crypto::Error::new(e))?;
        let key = match key_type {
            ArbitratingKey::Fund => {
                master_key.derive_priv(&secp, &DerivationPath::from_str("m/0/1/1").unwrap())
            }
            ArbitratingKey::Buy => {
                master_key.derive_priv(&secp, &DerivationPath::from_str("m/0/1/2").unwrap())
            }
            ArbitratingKey::Cancel => {
                master_key.derive_priv(&secp, &DerivationPath::from_str("m/0/1/3").unwrap())
            }
            ArbitratingKey::Refund => {
                master_key.derive_priv(&secp, &DerivationPath::from_str("m/0/1/4").unwrap())
            }
            ArbitratingKey::Punish => {
                master_key.derive_priv(&secp, &DerivationPath::from_str("m/0/1/5").unwrap())
            }
        };
        Ok(key.map_err(|e| crypto::Error::new(e))?.private_key)
    }

    pub fn get_pubkey(&self, key_type: ArbitratingKey) -> Result<PublicKey, crypto::Error> {
        let secp = Secp256k1::new();
        Ok(self.get_privkey(key_type)?.public_key(&secp))
    }
}

impl FromSeed<Arb> for Bitcoin {
    type Wallet = Wallet;

    fn get_pubkey(engine: &Wallet, key_type: ArbitratingKey) -> Result<PublicKey, crypto::Error> {
        engine.get_pubkey(key_type)
    }
}

impl Signatures for Bitcoin {
    type Wallet = Wallet;
    type Message = Sha256dHash;
    type Signature = Signature;
    type AdaptorSignature = ECDSAAdaptorSig;

    fn sign_with_key(
        _context: &Wallet,
        _key: &PublicKey,
        _msg: Sha256dHash,
    ) -> Result<Signature, crypto::Error> {
        todo!()
    }

    /// Verify a signature for a given message with the provided public key.
    fn verify_signature(
        _context: &Wallet,
        _key: &PublicKey,
        _msg: Sha256dHash,
        _sig: &Signature,
    ) -> Result<(), crypto::Error> {
        todo!()
    }

    /// Sign the message with the corresponding private key identified by the provided public key
    /// and encrypt it (create an adaptor signature) with the provided adaptor public key.
    fn adaptor_sign_with_key(
        _context: &Wallet,
        _key: &PublicKey,
        _adaptor: &PublicKey,
        _msg: Sha256dHash,
    ) -> Result<ECDSAAdaptorSig, crypto::Error> {
        todo!()
    }

    /// Verify a adaptor signature for a given message with the provided public key and the public
    /// adaptor key.
    fn verify_adaptor_signature(
        _context: &Wallet,
        _key: &PublicKey,
        _adaptor: &PublicKey,
        _msg: Sha256dHash,
        _sig: &ECDSAAdaptorSig,
    ) -> Result<(), crypto::Error> {
        todo!()
    }

    /// Finalize an adaptor signature (decrypt the signature) into an adapted signature (decrypted
    /// signatures) with the corresponding private key identified by the provided public key.
    fn adapt_signature(
        _context: &Wallet,
        _key: &PublicKey,
        _sig: ECDSAAdaptorSig,
    ) -> Result<Signature, crypto::Error> {
        todo!()
    }

    /// Recover the encryption key based on the adaptor signature and the decrypted signature.
    fn recover_key(
        _context: &Wallet,
        _sig: Signature,
        _adapted_sig: ECDSAAdaptorSig,
    ) -> PrivateKey {
        todo!()
    }
}
