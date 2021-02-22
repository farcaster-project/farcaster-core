//! Blockchain utilities

use bitcoin::hash_types::PubkeyHash;
use bitcoin::util::psbt::PartiallySignedTransaction;
use monero::cryptonote::hash::Hash;

use crate::roles::{Accordant, Arbitrating};

pub trait Blockchain {
    type AssetUnit;
    type PrivateKey;
    type PublicKey;
    type Commitment;

    fn id(&self) -> String;

    fn new() -> Self;
}

pub struct Bitcoin {}

impl Blockchain for Bitcoin {
    type AssetUnit = bitcoin::util::amount::Amount;
    type PrivateKey = secp256k1::key::SecretKey;
    type PublicKey = secp256k1::key::PublicKey;
    type Commitment = PubkeyHash;

    fn id(&self) -> String {
        String::from("btc")
    }

    fn new() -> Self {
        Bitcoin {}
    }
}

impl Arbitrating for Bitcoin {
    type Transaction = PartiallySignedTransaction;
    type Address = bitcoin::util::address::Address;
    /// Defines the signature format for the arbitrating blockchain
    type Signature = secp256k1::Signature;
}

pub struct Monero {}

impl Blockchain for Monero {
    type AssetUnit = u64;
    type PrivateKey = monero::util::key::PrivateKey;
    type PublicKey = monero::util::key::PublicKey;
    type Commitment = Hash;

    fn id(&self) -> String {
        String::from("xmr")
    }

    fn new() -> Self {
        Monero {}
    }
}

impl Accordant for Monero {}
