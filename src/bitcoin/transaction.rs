use std::fmt::Debug;
use std::marker::PhantomData;

use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
use bitcoin::util::address;
use bitcoin::util::psbt::{self, PartiallySignedTransaction};

#[cfg(feature = "experimental")]
use bitcoin::{hashes::sha256d::Hash, secp256k1::Signature, util::key::PublicKey, Amount};

use thiserror::Error;

use crate::bitcoin::{Bitcoin, Strategy};
use crate::consensus::{self, CanonicalBytes};
#[cfg(feature = "experimental")]
use crate::transaction::Transaction;
use crate::transaction::{Broadcastable, Error as FError, Finalizable, Linkable};

#[cfg(feature = "experimental")]
use crate::{
    bitcoin::segwitv0::{signature_hash, SegwitV0},
    script::ScriptPath,
    transaction::Witnessable,
};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataOutput {
    pub out_point: OutPoint,
    pub tx_out: TxOut,
    pub script_pubkey: Option<Script>,
}

pub trait SubTransaction: Debug {
    fn finalize(psbt: &mut PartiallySignedTransaction) -> Result<(), FError>;
}

#[derive(Debug)]
pub struct Tx<T: SubTransaction> {
    pub(crate) psbt: PartiallySignedTransaction,
    pub(crate) _t: PhantomData<T>,
}

#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
impl<T> Transaction<Bitcoin<SegwitV0>, MetadataOutput> for Tx<T>
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
            out_point: self.psbt.global.unsigned_tx.input[0]
                .previous_output
                .clone(),
            tx_out: self.psbt.inputs[0].witness_utxo.clone().unwrap(), // FIXME
            script_pubkey: self.psbt.inputs[0].witness_script.clone(),
        }
    }

    fn output_amount(&self) -> Amount {
        Amount::from_sat(self.psbt.global.unsigned_tx.output[0].value)
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

impl<T, S> Broadcastable<Bitcoin<S>> for Tx<T>
where
    T: SubTransaction,
    S: Strategy,
{
    fn extract(&self) -> bitcoin::blockdata::transaction::Transaction {
        self.psbt.clone().extract_tx()
    }
}

impl<T> Linkable<MetadataOutput> for Tx<T>
where
    T: SubTransaction,
{
    fn get_consumable_output(&self) -> Result<MetadataOutput, FError> {
        match self.psbt.global.unsigned_tx.output.len() {
            1 => (),
            2 => {
                if !self.psbt.global.unsigned_tx.is_coin_base() {
                    return Err(FError::new(Error::MultiUTXOUnsuported));
                }
            }
            _ => return Err(FError::new(Error::MultiUTXOUnsuported)),
        }

        Ok(MetadataOutput {
            out_point: OutPoint::new(self.psbt.global.unsigned_tx.txid(), 0),
            tx_out: self.psbt.global.unsigned_tx.output[0].clone(),
            script_pubkey: self.psbt.outputs[0].witness_script.clone(),
        })
    }
}

#[cfg(feature = "experimental")]
#[cfg_attr(docsrs, doc(cfg(feature = "experimental")))]
impl<T> Witnessable<Bitcoin<SegwitV0>> for Tx<T>
where
    T: SubTransaction,
{
    // FIXME this assume only one input
    fn generate_witness_message(&self, _path: ScriptPath) -> Result<Hash, FError> {
        let unsigned_tx = self.psbt.global.unsigned_tx.clone();
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

        let sighash_type = self.psbt.inputs[0]
            .sighash_type
            .ok_or(FError::new(Error::MissingSigHashType))?;

        Ok(signature_hash(txin, &script, value, sighash_type))
    }

    fn add_witness(&mut self, pubkey: PublicKey, sig: Signature) -> Result<(), FError> {
        let sighash_type = self.psbt.inputs[0]
            .sighash_type
            .ok_or(FError::new(Error::MissingSigHashType))?;
        let mut full_sig = sig.serialize_der().to_vec();
        full_sig.extend_from_slice(&[sighash_type.as_u32() as u8]);
        self.psbt.inputs[0].partial_sigs.insert(pubkey, full_sig);
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
