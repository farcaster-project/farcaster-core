use std::marker::PhantomData;

use bitcoin::blockdata::transaction::{SigHashType, TxIn, TxOut};
use bitcoin::secp256k1::Signature;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::PartiallySignedTransaction;

use farcaster_core::blockchain::{FeePolitic, FeeStrategy};
use farcaster_core::script;
use farcaster_core::transaction::{
    AdaptorSignable, Cancelable, Error as FError, Refundable, Signable,
};

use crate::bitcoin::fee::SatPerVByte;
use crate::bitcoin::transaction::{Error, MetadataOutput, SubTransaction, Tx};
use crate::bitcoin::{Address, Bitcoin, ECDSAAdaptorSig};

#[derive(Debug)]
pub struct Refund;

impl SubTransaction for Refund {
    fn finalize(_psbt: &mut PartiallySignedTransaction) -> Result<(), FError> {
        todo!()
    }
}

impl Refundable<Bitcoin, MetadataOutput> for Tx<Refund> {
    fn initialize(
        prev: &impl Cancelable<Bitcoin, MetadataOutput>,
        punish_lock: script::DataPunishableLock<Bitcoin>,
        refund_target: Address,
        _fee_strategy: &FeeStrategy<SatPerVByte>,
        _fee_politic: FeePolitic,
    ) -> Result<Self, FError> {
        let output_metadata = prev.get_consumable_output()?;

        let unsigned_tx = bitcoin::blockdata::transaction::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: output_metadata.out_point,
                script_sig: bitcoin::blockdata::script::Script::default(),
                sequence: punish_lock.timelock.as_u32(),
                witness: vec![],
            }],
            output: vec![TxOut {
                value: output_metadata.tx_out.value,
                script_pubkey: refund_target.0.script_pubkey(),
            }],
        };

        let mut psbt =
            PartiallySignedTransaction::from_unsigned_tx(unsigned_tx).map_err(Error::from)?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].sighash_type = Some(SigHashType::All);

        // TODO move the logic inside core
        //// Set the fees according to the given strategy
        //Bitcoin::set_fees(&mut psbt, fee_strategy, fee_politic)?;

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }
}

impl Signable<Bitcoin> for Tx<Refund> {
    fn generate_witness(&self, _privkey: &PrivateKey) -> Result<Signature, FError> {
        todo!()
    }

    fn verify_witness(&self, _pubkey: &PublicKey, _sig: Signature) -> Result<(), FError> {
        todo!()
    }
}

impl AdaptorSignable<Bitcoin> for Tx<Refund> {
    fn generate_adaptor_witness(
        &self,
        _privkey: &PrivateKey,
        _adaptor: &PublicKey,
    ) -> Result<ECDSAAdaptorSig, FError> {
        todo!()
    }

    fn verify_adaptor_witness(
        &self,
        _pubkey: &PublicKey,
        _adaptor: &PublicKey,
        _sig: ECDSAAdaptorSig,
    ) -> Result<(), FError> {
        todo!()
    }
}
