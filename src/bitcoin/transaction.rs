//! Bitcoin transactions framework. This module contains types shared across strategies.

use std::fmt::Debug;
use std::marker::PhantomData;

use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{EcdsaSighashType, OutPoint, TxIn, TxOut};
use bitcoin::util::address;
use bitcoin::util::ecdsa::EcdsaSig;
use bitcoin::util::psbt::{self, PartiallySignedTransaction};

#[cfg(feature = "experimental")]
use bitcoin::{
    secp256k1::{ecdsa::Signature, PublicKey},
    Amount,
};

use thiserror::Error;

use crate::consensus::{self, CanonicalBytes};
use crate::transaction::{Broadcastable, Error as FError, Finalizable, Linkable};
use bitcoin::hashes::sha256d::Hash as Sha256dHash;

#[cfg(feature = "experimental")]
use crate::{
    bitcoin::segwitv0::signature_hash,
    script::ScriptPath,
    transaction::{Transaction, Witnessable},
};

/// Concrete error type generated when manipulating Bitcoin transactions. The error can come from
/// more specialized context such as `Psbt`, `Address`, or `secp256k1`.
#[derive(Error, Debug)]
pub enum Error {
    /// Multi-input transaction is not supported
    #[error("Multi-input transaction is not supported")]
    MultiUTXOUnsuported,
    /// SigHash type is missing
    #[error("SigHash type is missing")]
    MissingSigHashType,
    /// Partially signed transaction error
    #[error("Partially signed transaction error: `{0}`")]
    Psbt(#[from] psbt::Error),
    /// Bitcoin address error
    #[error("Bitcoin address error: `{0}`")]
    Address(#[from] address::Error),
    /// Secp256k1 error
    #[error("Secp256k1 error: `{0}`")]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
    /// Bitcoin script error
    #[error("Bitcoin script error: `{0}`")]
    BitcoinScript(#[from] bitcoin::blockdata::script::Error),
}

impl From<Error> for FError {
    fn from(e: Error) -> FError {
        FError::new(e)
    }
}

/// A reference to some transaction output used to build new transaction on top of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataOutput {
    /// A reference to the transaction output with `txid` and `vout` index.
    pub out_point: OutPoint,
    /// A transaction output which defines the value (in satoshis) and the `script_pubkey`.
    pub tx_out: TxOut,
    pub script_pubkey: Option<Script>,
}

/// Defines the inner behaviour of a generic transaction [`Tx`].
pub trait SubTransaction: Debug {
    /// Defines the behaviour for finalizing the `PartiallySignedTransaction` from a generic
    /// transaction [`Tx`].
    fn finalize(psbt: &mut PartiallySignedTransaction) -> Result<(), FError>;
}

/// A general purpose Bitcoin transaction used in a swap context. This implements
/// [`crate::transaction`] traits.
#[derive(Debug)]
pub struct Tx<T: SubTransaction> {
    pub(crate) psbt: PartiallySignedTransaction,
    pub(crate) _t: PhantomData<T>,
}

#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
impl<T> Transaction<PartiallySignedTransaction, MetadataOutput, Amount> for Tx<T>
where
    T: SubTransaction,
{
    fn as_partial(&self) -> &PartiallySignedTransaction {
        &self.psbt
    }

    fn as_partial_mut(&mut self) -> &mut PartiallySignedTransaction {
        &mut self.psbt
    }

    fn to_partial(self) -> PartiallySignedTransaction {
        self.psbt
    }

    fn from_partial(partial: PartiallySignedTransaction) -> Self {
        Self {
            psbt: partial,
            _t: PhantomData,
        }
    }

    fn based_on(&self) -> MetadataOutput {
        MetadataOutput {
            out_point: self.psbt.unsigned_tx.input[0].previous_output,
            tx_out: self.psbt.inputs[0].witness_utxo.clone().unwrap(), // FIXME
            script_pubkey: self.psbt.inputs[0].witness_script.clone(),
        }
    }

    fn output_amount(&self) -> Amount {
        Amount::from_sat(self.psbt.unsigned_tx.output[0].value)
    }
}

impl<T> Finalizable for Tx<T>
where
    T: SubTransaction,
{
    fn finalize(&mut self) -> Result<(), FError> {
        T::finalize(&mut self.psbt)
    }
}

impl<T> Broadcastable<bitcoin::Transaction> for Tx<T>
where
    T: SubTransaction,
{
    fn extract(&self) -> bitcoin::Transaction {
        self.psbt.clone().extract_tx()
    }
}

impl<T> Linkable<MetadataOutput> for Tx<T>
where
    T: SubTransaction,
{
    fn get_consumable_output(&self) -> Result<MetadataOutput, FError> {
        match self.psbt.unsigned_tx.output.len() {
            1 => (),
            2 => {
                if !self.psbt.unsigned_tx.is_coin_base() {
                    return Err(FError::new(Error::MultiUTXOUnsuported));
                }
            }
            _ => return Err(FError::new(Error::MultiUTXOUnsuported)),
        }

        Ok(MetadataOutput {
            out_point: OutPoint::new(self.psbt.unsigned_tx.txid(), 0),
            tx_out: self.psbt.unsigned_tx.output[0].clone(),
            script_pubkey: self.psbt.outputs[0].witness_script.clone(),
        })
    }
}

#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
impl<T> Witnessable<Sha256dHash, PublicKey, Signature> for Tx<T>
where
    T: SubTransaction,
{
    /// ## Safety
    /// This function is used for generating the witness message for all transactions but not
    /// funding. So implying only 1 input is valid as all templates only have 1 input.
    fn generate_witness_message(&self, _path: ScriptPath) -> Result<Sha256dHash, FError> {
        let unsigned_tx = self.psbt.unsigned_tx.clone();
        let txin = TxInRef::new(&unsigned_tx, 0);

        let witness_utxo = self.psbt.inputs[0]
            .witness_utxo
            .clone()
            .ok_or(FError::MissingWitness)?;

        let script = self.psbt.inputs[0]
            .witness_script
            .clone()
            .ok_or(FError::MissingWitness)?;
        let value = witness_utxo.value;

        Ok(signature_hash(txin, &script, value, EcdsaSighashType::All))
    }

    fn add_witness(&mut self, pubkey: PublicKey, sig: Signature) -> Result<(), FError> {
        let sig_all = EcdsaSig::sighash_all(sig);
        self.psbt.inputs[0]
            .partial_sigs
            .insert(bitcoin::PublicKey::new(pubkey), sig_all);
        Ok(())
    }
}

/// A borrowed reference to a transaction input.
#[derive(Debug, Copy, Clone)]
pub struct TxInRef<'a> {
    pub(crate) transaction: &'a bitcoin::blockdata::transaction::Transaction,
    pub(crate) index: usize,
}

impl<'a> TxInRef<'a> {
    /// Constructs a reference to the input with the given index of the given transaction.
    pub fn new(
        transaction: &'a bitcoin::blockdata::transaction::Transaction,
        index: usize,
    ) -> TxInRef<'a> {
        assert!(transaction.input.len() > index);
        TxInRef { transaction, index }
    }

    /// Returns a reference to the borrowed transaction.
    pub fn transaction(&self) -> &bitcoin::blockdata::transaction::Transaction {
        self.transaction
    }

    /// Returns a reference to the input.
    pub fn input(&self) -> &TxIn {
        &self.transaction.input[self.index]
    }

    /// Returns the index of input.
    pub fn index(&self) -> usize {
        self.index
    }
}

impl<'a> AsRef<TxIn> for TxInRef<'a> {
    fn as_ref(&self) -> &TxIn {
        self.input()
    }
}

impl CanonicalBytes for bitcoin::Transaction {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        bitcoin::consensus::encode::serialize(&self)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        bitcoin::consensus::encode::deserialize(bytes).map_err(consensus::Error::new)
    }
}

impl CanonicalBytes for PartiallySignedTransaction {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        bitcoin::consensus::encode::serialize(&self)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        bitcoin::consensus::encode::deserialize(bytes).map_err(consensus::Error::new)
    }
}
