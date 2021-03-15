//! Defines and implements all the traits for Bitcoin

use bitcoin::blockdata::transaction;
use bitcoin::hash_types::PubkeyHash;
use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::amount::Amount;
use bitcoin::util::psbt::PartiallySignedTransaction;
use secp256k1::key::PublicKey;
use secp256k1::key::SecretKey;
use secp256k1::Signature;

use crate::blockchain::{Blockchain, Fee, FeeStrategy, FeeUnit, Onchain};
use crate::crypto::{Commitment, CrossGroupDLEQ, Curve, ECDSAScripts, Keys, Script, Signatures};
use crate::monero::{Ed25519, Monero};
use crate::role::Arbitrating;
use crate::transaction::{
    Broadcastable, Failable, Forkable, Funding, Linkable, Lock, Spendable, Transaction,
};

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

#[derive(Clone, Copy)]
pub enum FeeStrategies {
    Fixed(SatPerVByte),
    Range(SatPerVByte, SatPerVByte),
}

impl FeeStrategy for Bitcoin {
    type FeeStrategy = FeeStrategies;

    fn fixed_fee(fee: Self::FeeUnit) -> Self::FeeStrategy {
        FeeStrategies::Fixed(fee)
    }

    fn range_fee(fee_low: Self::FeeUnit, fee_high: Self::FeeUnit) -> Self::FeeStrategy {
        FeeStrategies::Range(fee_low, fee_high)
    }
}

impl FeeUnit for Bitcoin {
    type FeeUnit = SatPerVByte;
}

impl Fee for Bitcoin {
    /// Calculates and sets the fees on the given transaction and return the fees set
    fn set_fees(_tx: &mut PartiallySignedTransaction, _strategy: &FeeStrategies) -> SatPerVByte {
        todo!()
    }

    /// Validates that the fees for the given transaction are set accordingly to the strategy
    fn validate_fee(_tx: &PartiallySignedTransaction, _strategy: &FeeStrategies) -> bool {
        todo!()
    }
}

impl Arbitrating for Bitcoin {
    /// Defines the transaction format for the arbitrating blockchain
    type Address = Address;

    /// Defines the type of timelock used for the arbitrating transactions
    type Timelock = u32;
}

impl Onchain for Bitcoin {
    /// Defines the transaction format used to transfer partial transaction between participant for
    /// the arbitrating blockchain
    type PartialTransaction = PartiallySignedTransaction;

    /// Defines the finalized transaction format for the arbitrating blockchain
    type Transaction = transaction::Transaction;
}

pub struct Secp256k1;

impl Curve for Bitcoin {
    /// Eliptic curve
    type Curve = Secp256k1;
}

/// Produces a zero-knowledge proof of knowledge of the same relation k between two pairs of
/// elements in the same group, i.e. `(G, R')` and `(T, R)`.
pub struct PDLEQ;

impl Script for Bitcoin {
    type Script = ECDSAScripts;
}

impl Keys for Bitcoin {
    type PrivateKey = SecretKey;
    type PublicKey = PublicKey;
}

impl Commitment for Bitcoin {
    type Commitment = PubkeyHash;
}

impl Signatures for Bitcoin {
    type Signature = Signature;
    type AdaptorSignature = (Signature, PublicKey, PDLEQ);
}

//// TODO: implement on another struct or on a generic Bitcoin<T>
// impl Crypto for Bitcoin {
//     type PrivateKey = SecretKey;
//     type PublicKey = secp256k1::schnorrsig::PublicKey;
//     type Commitment = PubkeyHash;
// }

pub struct RingSignatureProof;

impl CrossGroupDLEQ<Bitcoin, Monero> for RingSignatureProof {}

impl PartialEq<Ed25519> for Secp256k1 {
    fn eq(&self, _other: &Ed25519) -> bool {
        todo!()
    }
}

impl PartialEq<Secp256k1> for Ed25519 {
    fn eq(&self, other: &Secp256k1) -> bool {
        other.eq(self)
    }
}

// =========================================================================================
// =============================     TRANSACTIONS    =======================================
// =========================================================================================

#[derive(Debug)]
pub struct FundingTx {
    privkey: bitcoin::util::key::PrivateKey,
    network: Network,
    seen_tx: Option<transaction::Transaction>,
}

impl Failable for FundingTx {
    type Err = ();
}

impl Linkable<Bitcoin> for FundingTx {
    type Output = transaction::OutPoint;

    fn get_consumable_output(&self) -> Result<transaction::OutPoint, ()> {
        match &self.seen_tx {
            Some(t) => {
                // More than one UTXO is not supported
                if t.output.len() != 1 {
                    return Err(());
                }
                // vout is always 0 because output len is 1
                Ok(transaction::OutPoint::new(t.txid(), 0))
            }
            // The transaction has not been see yet, cannot infer the UTXO
            None => Err(()),
        }
    }
}

impl Spendable<Bitcoin> for FundingTx {
    type Witness = ();

    fn generate_witness(&self) -> Result<(), ()> {
        todo!()
    }
}

impl Funding<Bitcoin> for FundingTx {
    fn initialize(privkey: SecretKey) -> Result<Self, ()> {
        let privkey = bitcoin::util::key::PrivateKey {
            compressed: true,
            network: Network::Bitcoin,
            key: privkey,
        };
        Ok(FundingTx {
            privkey,
            network: Network::Bitcoin,
            seen_tx: None,
        })
    }

    fn get_address(&self) -> Result<Address, ()> {
        let pubkey = bitcoin::util::key::PublicKey::from_private_key(
            &secp256k1::Secp256k1::new(),
            &self.privkey,
        );
        Ok(Address::p2wpkh(&pubkey, self.network).expect("FIXME latter"))
    }

    fn update(&mut self, args: transaction::Transaction) -> Result<(), ()> {
        self.seen_tx = Some(args);
        Ok(())
    }
}

#[derive(Debug)]
pub struct LockTx {
    tx: transaction::Transaction,
    pubkeys: (bitcoin::util::key::PublicKey, bitcoin::util::key::PublicKey),
    network: Network,
}

impl Failable for LockTx {
    type Err = ();
}

impl Transaction<Bitcoin> for LockTx {
    fn to_partial(&self) -> Option<PartiallySignedTransaction> {
        todo!()
    }

    fn from_partial(tx: &PartiallySignedTransaction) -> Option<Self> {
        todo!()
    }
}

impl Broadcastable<Bitcoin> for LockTx {
    fn finalize<T>(&self, args: T) -> transaction::Transaction {
        todo!()
    }
}

impl Linkable<Bitcoin> for LockTx {
    type Output = ();

    fn get_consumable_output(&self) -> Result<(), ()> {
        todo!()
    }
}

impl Spendable<Bitcoin> for LockTx {
    type Witness = ();

    fn generate_witness(&self) -> Result<(), ()> {
        todo!()
    }
}

impl Forkable<Bitcoin> for LockTx {
    fn generate_failure_witness<T>(&self, args: T) -> Result<(), ()> {
        todo!()
    }
}

impl Lock<Bitcoin> for LockTx {
    fn initialize(
        prev: &impl Funding<Bitcoin>,
        timelock: u32,
        fee_strategy: &impl FeeStrategy,
        pubkeys: (PublicKey, PublicKey),
    ) -> Result<Self, ()> {
        todo!()
    }
}
