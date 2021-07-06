use std::marker::PhantomData;

use bitcoin::blockdata::transaction::{SigHashType, TxIn, TxOut};
use bitcoin::util::psbt::PartiallySignedTransaction;

use crate::script;
use crate::transaction::{Cancelable, Error, Punishable};

use crate::chain::bitcoin::transaction::{MetadataOutput, SubTransaction, Tx};
use crate::chain::bitcoin::{Address, Bitcoin};

#[derive(Debug)]
pub struct Punish;

impl SubTransaction for Punish {
    fn finalize(psbt: &mut PartiallySignedTransaction) -> Result<(), Error> {
        let script = psbt.inputs[0]
            .witness_script
            .clone()
            .ok_or(Error::MissingWitness)?;

        let (_, full_sig) = psbt.inputs[0]
            .partial_sigs
            .iter()
            .next()
            .ok_or(Error::MissingSignature)?;

        psbt.inputs[0].final_script_witness = Some(vec![
            full_sig.clone(), // sig
            vec![],           // OP_FALSE
            script.into_bytes(),
        ]);
        Ok(())
    }
}

impl Punishable<Bitcoin, MetadataOutput> for Tx<Punish> {
    fn initialize(
        prev: &impl Cancelable<Bitcoin, MetadataOutput>,
        punish_lock: script::DataPunishableLock<Bitcoin>,
        destination_target: Address,
    ) -> Result<Self, Error> {
        let output_metadata = prev.get_consumable_output()?;

        let unsigned_tx = bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: output_metadata.out_point,
                script_sig: bitcoin::Script::default(),
                sequence: punish_lock.timelock.as_u32(),
                witness: vec![],
            }],
            output: vec![TxOut {
                value: output_metadata.tx_out.value,
                script_pubkey: destination_target.0.script_pubkey(),
            }],
        };

        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(unsigned_tx)
            .map_err(super::Error::from)?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].witness_script = output_metadata.script_pubkey;
        psbt.inputs[0].sighash_type = Some(SigHashType::All);

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }
}
