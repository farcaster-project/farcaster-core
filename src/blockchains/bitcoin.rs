//! Defines and implements all the traits for Bitcoin

use bitcoin::hash_types::PubkeyHash;
use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::amount::Amount;
use bitcoin::util::psbt::PartiallySignedTransaction;
use secp256k1::key::PublicKey;
use secp256k1::key::SecretKey;
use secp256k1::Signature;

use crate::blockchains::{Blockchain, Fee, FixeFee};
use crate::crypto::{Crypto, ECDSAScripts, TrSchnorrScripts};
use crate::roles::Arbitrating;

#[derive(Clone, Copy)]
pub struct Bitcoin;

impl Blockchain for Bitcoin {
    /// Type for the traded asset unit
    type AssetUnit = Amount;

    /// Type of the blockchain identifier
    type Id = String;

    /// Type of the chain identifier
    type ChainId = Network;

    /// Returns the blockchain identifier
    fn id(&self) -> String {
        String::from("btc")
    }

    /// Returns the chain identifier
    fn chain_id(&self) -> Network {
        Network::Bitcoin
    }

    /// Create a new Bitcoin blockchain
    fn new() -> Self {
        Bitcoin {}
    }
}

#[derive(Clone, Copy)]
pub struct SatPerVByte(Amount);

impl SatPerVByte {
    pub fn from_sat(satoshi: u64) -> Self {
        SatPerVByte(Amount::from_sat(satoshi))
    }
}

impl Fee<FixeFee<Bitcoin>> for Bitcoin {
    /// Type for describing the fees of a blockchain
    type FeeUnit = SatPerVByte;

    /// Calculates and sets the fees on the given transaction and return the fees set
    fn set_fees(_tx: &mut PartiallySignedTransaction, _strategy: &FixeFee<Bitcoin>) -> SatPerVByte {
        todo!()
    }

    /// Validates that the fees for the given transaction are set accordingly to the strategy
    fn validate_fee(_tx: &PartiallySignedTransaction, _strategy: &FixeFee<Bitcoin>) -> bool {
        todo!()
    }
}

impl Arbitrating for Bitcoin {
    /// Defines the address format for the arbitrating blockchain
    type Transaction = PartiallySignedTransaction;

    /// Defines the transaction format for the arbitrating blockchain
    type Address = Address;

    //// Defines the type of timelock used for the arbitrating transactions
    type Timelock = u32;
}

impl Crypto<ECDSAScripts> for Bitcoin {
    type PrivateKey = SecretKey;
    type PublicKey = PublicKey;
    type Commitment = PubkeyHash;
    type Signature = Signature;
}

impl Crypto<TrSchnorrScripts> for Bitcoin {
    type PrivateKey = SecretKey;
    type PublicKey = secp256k1::schnorrsig::PublicKey;
    type Commitment = PubkeyHash;
    type Signature = secp256k1::schnorrsig::Signature;
}
