use std::fmt::Debug;
use std::marker::PhantomData;

use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{OutPoint, SigHashType, TxIn, TxOut};
use bitcoin::hashes::sha256d::Hash;
use bitcoin::secp256k1::{Message, Secp256k1, Signature, Signing};
use bitcoin::util::address;
use bitcoin::util::bip143::SigHashCache;
use bitcoin::util::key::PublicKey;
use bitcoin::util::psbt::{self, PartiallySignedTransaction};

use thiserror::Error;

use crate::script::ScriptPath;
use crate::transaction::{
    Broadcastable, Error as FError, Finalizable, Linkable, Transaction, Witnessable,
};

use crate::chain::bitcoin::{Amount, Bitcoin};

pub mod buy;
pub mod cancel;
pub mod funding;
pub mod lock;
pub mod punish;
pub mod refund;

pub use buy::Buy;
pub use cancel::Cancel;
pub use funding::Funding;
pub use lock::Lock;
pub use punish::Punish;
pub use refund::Refund;

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
    PSBT(#[from] psbt::Error),
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
    psbt: PartiallySignedTransaction,
    _t: PhantomData<T>,
}

impl<T> Transaction<Bitcoin, MetadataOutput> for Tx<T>
where
    T: SubTransaction,
{
    fn partial(&self) -> &PartiallySignedTransaction {
        &self.psbt
    }

    fn partial_mut(&mut self) -> &mut PartiallySignedTransaction {
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

impl<T> Broadcastable<Bitcoin> for Tx<T>
where
    T: SubTransaction,
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

impl<T> Witnessable<Bitcoin> for Tx<T>
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
    transaction: &'a bitcoin::blockdata::transaction::Transaction,
    index: usize,
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

/// Computes the [`BIP-143`][bip-143] compliant sighash for a [`SIGHASH_ALL`][sighash_all]
/// signature for the given input.
///
/// [bip-143]: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
/// [sighash_all]: https://bitcoin.org/en/developer-guide#signature-hash-types
pub fn signature_hash<'a>(
    txin: TxInRef<'a>,
    script: &Script,
    value: u64,
    sighash_type: SigHashType,
) -> Hash {
    SigHashCache::new(txin.transaction)
        .signature_hash(txin.index, script, value, sighash_type)
        .as_hash()
}

/// Computes the [`BIP-143`][bip-143] compliant signature for the given input.
/// [Read more...][signature-hash]
///
/// [bip-143]: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
/// [signature-hash]: fn.signature_hash.html
pub fn sign_input<'a, C>(
    context: &mut Secp256k1<C>,
    txin: TxInRef<'a>,
    script: &Script,
    value: u64,
    sighash_type: SigHashType,
    secret_key: &bitcoin::secp256k1::SecretKey,
) -> Result<Signature, bitcoin::secp256k1::Error>
where
    C: Signing,
{
    // Computes sighash.
    let sighash = signature_hash(txin, script, value, sighash_type);
    // Makes signature.
    let msg = Message::from_slice(&sighash[..])?;
    let mut sig = context.sign(&msg, secret_key);
    sig.normalize_s();
    Ok(sig)
}
