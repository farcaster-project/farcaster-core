use std::marker::PhantomData;

use bitcoin::blockdata::transaction::{SigHashType, TxIn, TxOut};
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::Address;

use farcaster_core::script;
use farcaster_core::transaction::{Cancelable, Error as FError, Refundable};

use crate::bitcoin::transaction::{Error, MetadataOutput, SubTransaction, Tx};
use crate::bitcoin::Bitcoin;

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
                script_pubkey: refund_target.script_pubkey(),
            }],
        };

        let mut psbt =
            PartiallySignedTransaction::from_unsigned_tx(unsigned_tx).map_err(Error::from)?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].witness_script = output_metadata.script_pubkey;
        psbt.inputs[0].sighash_type = Some(SigHashType::All);

        // TODO move the logic inside core
        //// Set the fees according to the given strategy
        //Bitcoin::set_fees(&mut psbt, fee_strategy, fee_politic)?;

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }

    fn verify_template(
        &self,
        _punish_lock: script::DataPunishableLock<Bitcoin>,
        _refund_target: Address,
    ) -> Result<(), FError> {
        todo!()
    }
}
