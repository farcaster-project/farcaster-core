//! Defines and implements all the traits for Bitcoin

use bitcoin::blockdata::transaction;
use bitcoin::hash_types::PubkeyHash;
use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::amount::Amount;
use bitcoin::util::psbt::PartiallySignedTransaction;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::transaction::{OutPoint, SigHashType, TxIn, TxOut};
use bitcoin::hash_types::Txid;

use bitcoin::util::key::{PrivateKey, PublicKey};
//use secp256k1::key::PublicKey;
//use secp256k1::key::SecretKey;
use secp256k1::Signature;

use crate::blockchain::{
    Blockchain, Fee, FeePolitic, FeeStrategy, FeeStrategyError, FeeUnit, Onchain,
};
use crate::crypto::{Commitment, CrossGroupDLEQ, Curve, ECDSAScripts, Keys, Script, Signatures};
use crate::monero::{Ed25519, Monero};
use crate::role::Arbitrating;
use crate::script;
use crate::transaction::{Broadcastable, Failable, Funding, Linkable, Lock, Transaction};

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

#[derive(Clone, PartialOrd, PartialEq)]
pub struct SatPerVByte(Amount);

impl SatPerVByte {
    pub fn from_sat(satoshi: u64) -> Self {
        SatPerVByte(Amount::from_sat(satoshi))
    }

    pub fn as_sat(&self) -> u64 {
        self.0.as_sat()
    }

    pub fn as_native_unit(&self) -> Amount {
        self.0
    }
}

#[derive(Clone)]
pub enum FeeStrategies {
    Fixed(SatPerVByte),
    Range(std::ops::Range<SatPerVByte>),
}

impl FeeUnit for FeeStrategies {
    type FeeUnit = SatPerVByte;
}

impl FeeStrategy for FeeStrategies {
    fn fixed_fee(fee: Self::FeeUnit) -> Self {
        FeeStrategies::Fixed(fee)
    }

    fn range_fee(fee_low: Self::FeeUnit, fee_high: Self::FeeUnit) -> Self {
        if fee_low > fee_high {
            FeeStrategies::Fixed(fee_high)
        } else {
            FeeStrategies::Range(std::ops::Range {
                start: fee_low,
                end: fee_high,
            })
        }
    }
}

impl Fee for Bitcoin {
    type FeeStrategy = FeeStrategies;

    /// Calculates and sets the fees on the given transaction and return the fees set
    fn set_fees(
        tx: &mut PartiallySignedTransaction,
        strategy: &FeeStrategies,
        politic: FeePolitic,
    ) -> Result<Amount, FeeStrategyError> {
        // Get the available amount on the transaction
        let inputs: Result<Vec<TxOut>, FeeStrategyError> = tx
            .inputs
            .iter()
            .map(|psbt_in| {
                psbt_in
                    .witness_utxo
                    .clone()
                    .ok_or(FeeStrategyError::MissingInputsMetadata)
            })
            .collect();
        let input_sum = Amount::from_sat(inputs?.iter().map(|txout| txout.value).sum());

        // FIXME This does not account for witnesses
        // Get the transaction weight
        let weight = tx.global.unsigned_tx.get_weight() as u64;

        // Compute the fee amount to set in total
        let fee_amount = match strategy {
            FeeStrategies::Fixed(sat_per_vbyte) => {
                sat_per_vbyte.as_native_unit().checked_mul(weight)
            }
            FeeStrategies::Range(range) => match politic {
                FeePolitic::Aggressive => range.start.as_native_unit().checked_mul(weight),
                FeePolitic::Conservative => range.end.as_native_unit().checked_mul(weight),
            },
        }
        .ok_or_else(|| FeeStrategyError::AmountOfFeeTooHigh)?;

        if tx.global.unsigned_tx.output.len() != 1 {
            return Err(FeeStrategyError::MultiOutputUnsupported);
        }

        // Apply the fee on the first output
        tx.global.unsigned_tx.output[0].value = input_sum
            .checked_sub(fee_amount)
            .ok_or_else(|| FeeStrategyError::NotEnoughAssets)?
            .as_sat();

        // Return the fee amount set in native blockchain asset unit
        Ok(fee_amount)
    }

    /// Validates that the fees for the given transaction are set accordingly to the strategy
    fn validate_fee(
        _tx: &PartiallySignedTransaction,
        _strategy: &FeeStrategies,
        _politic: FeePolitic,
    ) -> Result<bool, FeeStrategyError> {
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
    type PrivateKey = PrivateKey;
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
    pubkey: PublicKey,
    seen_tx: Option<transaction::Transaction>,
}

impl Failable for FundingTx {
    type Err = ();
}

#[derive(Debug)]
pub struct MetadataFundingOutput {
    pub out_point: transaction::OutPoint,
    pub tx_out: TxOut,
}

impl Linkable<Bitcoin> for FundingTx {
    type Output = MetadataFundingOutput;

    fn get_consumable_output(&self) -> Result<MetadataFundingOutput, ()> {
        match &self.seen_tx {
            Some(t) => {
                // More than one UTXO is not supported
                if t.output.len() != 1 {
                    return Err(());
                }
                // vout is always 0 because output len is 1
                Ok(MetadataFundingOutput {
                    out_point: transaction::OutPoint::new(t.txid(), 0),
                    tx_out: t.output[0].clone(),
                })
            }
            // The transaction has not been see yet, cannot infer the UTXO
            None => Err(()),
        }
    }
}

//impl<'a> Spendable<Bitcoin> for FundingTx<'a> {
//    type Witness = ();
//
//    fn generate_witness(&self) -> Result<(), ()> {
//        todo!()
//    }
//}

impl Funding<Bitcoin> for FundingTx {
    fn initialize(pubkey: PublicKey) -> Result<Self, ()> {
        Ok(FundingTx {
            pubkey,
            seen_tx: None,
        })
    }

    fn get_address(&self) -> Result<Address, ()> {
        // FIXME: this always produce mainnet addresses
        Ok(Address::p2wpkh(&self.pubkey, Network::Bitcoin).map_err(|_| ())?)
    }

    fn update(&mut self, args: transaction::Transaction) -> Result<(), ()> {
        self.seen_tx = Some(args);
        Ok(())
    }
}

#[derive(Debug)]
pub struct LockTx {
    psbt: PartiallySignedTransaction,
}

impl Failable for LockTx {
    type Err = ();
}

impl Transaction<Bitcoin> for LockTx {
    fn to_partial(&self) -> Option<PartiallySignedTransaction> {
        Some(self.psbt.clone())
    }
}

impl Broadcastable<Bitcoin> for LockTx {
    fn finalize(&self) -> transaction::Transaction {
        self.psbt.clone().extract_tx()
    }
}

impl Linkable<Bitcoin> for LockTx {
    type Output = ();

    fn get_consumable_output(&self) -> Result<(), ()> {
        todo!()
    }
}

//impl Spendable<Bitcoin> for LockTx {
//    type Witness = ();
//
//    fn generate_witness(&self) -> Result<(), ()> {
//        todo!()
//    }
//}
//
//impl Forkable<Bitcoin> for LockTx {
//    fn generate_failure_witness(&self) -> Result<(), ()> {
//        todo!()
//    }
//}

impl Lock<Bitcoin> for LockTx {
    /// Type returned by the impl of a Funding tx
    type Input = MetadataFundingOutput;

    fn initialize(
        prev: &impl Funding<Bitcoin, Output = MetadataFundingOutput>,
        lock: script::Lock<Bitcoin>,
        fee_strategy: &FeeStrategies,
    ) -> Result<Self, ()> {
        let script = Builder::new()
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&lock.success.alice)
            .push_key(&lock.success.bob)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_int(lock.timelock.into())
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&lock.failure.alice)
            .push_key(&lock.failure.bob)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();

        let output_metadata = prev.get_consumable_output().map_err(|_| ())?;

        let unsigned_tx = transaction::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: output_metadata.out_point,
                script_sig: bitcoin::blockdata::script::Script::default(),
                sequence: 4294967295,
                witness: vec![],
            }],
            output: vec![TxOut {
                value: output_metadata.tx_out.value,
                script_pubkey: script.to_v0_p2wsh(),
            }],
        };

        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(unsigned_tx).map_err(|_| ())?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].sighash_type = Some(SigHashType::All);

        // Set the script witness of the output
        psbt.outputs[0].witness_script = Some(script);

        // Set the fees according to the given strategy
        // FIXME FeePolitic is a global argument
        Bitcoin::set_fees(&mut psbt, fee_strategy, FeePolitic::Aggressive).map_err(|_| ())?;

        Ok(LockTx { psbt })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::DoubleKeys;
    use crate::transaction::Lock;

    use bitcoin::blockdata::opcodes;
    use bitcoin::blockdata::script::{Builder, Script};
    use bitcoin::blockdata::transaction::{OutPoint, SigHashType, TxIn, TxOut};
    use bitcoin::consensus::encode::{deserialize, serialize};
    use bitcoin::hash_types::Txid;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::secp256k1::{Message, Secp256k1, SerializedSignature};
    use bitcoin::util::key::{PrivateKey, PublicKey};
    use bitcoin::util::psbt;
    use bitcoin::Transaction;

    #[test]
    fn create_funding() {
        let secp = Secp256k1::new();

        let privkey: PrivateKey =
            PrivateKey::from_wif("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D").unwrap();
        let pubkey = PublicKey::from_private_key(&secp, &privkey);

        let mut funding = FundingTx::initialize(pubkey).unwrap();
        println!("{}", funding.get_address().unwrap());

        let funding_tx_seen = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_hex(
                        "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389",
                    )
                    .unwrap(),
                    vout: 1,
                },
                script_sig: Script::from_hex("160014be18d152a9b012039daf3da7de4f53349eecb985")
                    .unwrap(),
                sequence: 4294967295,
                witness: vec![Vec::from_hex(
                    "03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105",
                )
                .unwrap()],
            }],
            output: vec![TxOut {
                value: 10_000_000,
                script_pubkey: Script::new_v0_wpkh(&pubkey.wpubkey_hash().unwrap()),
            }],
        };
        funding.update(funding_tx_seen).unwrap();
        println!("{:?}", funding.get_consumable_output().unwrap());

        let lock = script::Lock {
            timelock: 10,
            success: DoubleKeys::new(pubkey, pubkey),
            failure: DoubleKeys::new(pubkey, pubkey),
        };

        let fee = FeeStrategies::fixed_fee(SatPerVByte::from_sat(20));
        let lock = LockTx::initialize(&funding, lock, &fee).unwrap();
        println!("{:#?}", lock);

        assert!(false);
    }
}
