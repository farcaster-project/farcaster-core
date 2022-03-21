//! Implementation of a Taproot strategy with on-chain scripts for the arbitrating blockchain
//! as Bitcoin. Inner implementation of [`BitcoinTaproot`].

use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::str::FromStr;

use crate::bitcoin::taproot::funding::Funding;

use crate::bitcoin::{Bitcoin, BitcoinTaproot, Btc, Strategy};
use crate::consensus::{self, CanonicalBytes};
use crate::crypto::{Keys, SharedKeyId, SharedSecretKeys, Signatures};
//use crate::role::Arbitrating;

use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::secp256k1::{constants::SECRET_KEY_SIZE, schnorr::Signature, KeyPair, XOnlyPublicKey};

pub mod funding;
pub mod lock;

/// Funding the swap creating a Taproot (SegWit v1) output.
pub type FundingTx = Funding;

/// Inner type for the Taproot strategy with on-chain scripts.
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct Taproot;

impl Strategy for Taproot {}

impl fmt::Display for Bitcoin<Taproot> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Bitcoin<Taproot>")
    }
}

impl FromStr for Bitcoin<Taproot> {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Taproot" | "taproot" => Ok(Self::new()),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl From<BitcoinTaproot> for Btc {
    fn from(v: BitcoinTaproot) -> Self {
        Self::Taproot(v)
    }
}

//impl Arbitrating for Bitcoin<Taproot> {}

impl TryFrom<Btc> for Bitcoin<Taproot> {
    type Error = consensus::Error;

    fn try_from(v: Btc) -> Result<Self, consensus::Error> {
        match v {
            Btc::Taproot(v) => Ok(v),
            _ => Err(consensus::Error::TypeMismatch),
        }
    }
}

impl Keys for Bitcoin<Taproot> {
    type SecretKey = KeyPair;
    type PublicKey = XOnlyPublicKey;

    fn extra_keys() -> Vec<u16> {
        // No extra key
        vec![]
    }
}

impl CanonicalBytes for XOnlyPublicKey {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.serialize().as_ref().into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        XOnlyPublicKey::from_slice(bytes).map_err(consensus::Error::new)
    }
}

/// Schnorr secret key shareable over the network if needed by the protocol.
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct SecretSharedKey([u8; SECRET_KEY_SIZE]);

impl SecretSharedKey {
    /// Return a slice to the secret key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the secret key bytes.
    pub fn to_bytes(self) -> [u8; SECRET_KEY_SIZE] {
        self.0
    }
}

impl CanonicalBytes for SecretSharedKey {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.0.into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        Ok(SecretSharedKey(
            bytes.try_into().map_err(consensus::Error::new)?,
        ))
    }
}

impl SharedSecretKeys for Bitcoin<Taproot> {
    type SharedSecretKey = SecretSharedKey;

    fn shared_keys() -> Vec<SharedKeyId> {
        // No shared key in Bitcoin, transparent ledger
        vec![]
    }
}

impl Signatures for Bitcoin<Taproot> {
    type Message = Sha256dHash;
    type Signature = Signature;
    type EncryptedSignature = Signature;
}

impl CanonicalBytes for Signature {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        (*self.as_ref()).into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        Signature::from_slice(bytes).map_err(consensus::Error::new)
    }
}
