use std::marker::PhantomData;

use bitcoin::blockdata::transaction::{TxIn, TxOut};
use bitcoin::blockdata::witness::Witness;
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::Amount;

use crate::script;
use crate::transaction::{Error as FError, Fundable, Lockable};

use crate::bitcoin::segwitv0::{CoopLock, SegwitV0};
use crate::bitcoin::timelock::CSVTimelock;
use crate::bitcoin::transaction::{Error, MetadataOutput, SubTransaction, Tx};
use crate::bitcoin::Bitcoin;

#[derive(Debug)]
pub struct Lock;

impl SubTransaction for Lock {
    fn finalize(psbt: &mut PartiallySignedTransaction) -> Result<(), FError> {
        let (pubkey, full_sig) = psbt.inputs[0]
            .partial_sigs
            .iter()
            .next()
            .ok_or(FError::MissingSignature)?;
        psbt.inputs[0].final_script_witness = Some(Witness::from_vec(vec![
            full_sig.to_vec(),
            pubkey.serialize().to_vec(),
        ]));
        Ok(())
    }
}

impl Lockable<Bitcoin<SegwitV0>, MetadataOutput> for Tx<Lock> {
    fn initialize(
        prev: &impl Fundable<Bitcoin<SegwitV0>, MetadataOutput>,
        lock: script::DataLock<Bitcoin<SegwitV0>>,
        target_amount: Amount,
    ) -> Result<Self, FError> {
        let script = CoopLock::script(lock);
        let output_metadata = prev.get_consumable_output()?;

        if output_metadata.tx_out.value < target_amount.as_sat() {
            return Err(FError::NotEnoughAssets);
        }

        let unsigned_tx = bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: output_metadata.out_point,
                script_sig: bitcoin::Script::default(),
                sequence: CSVTimelock::disable(),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: target_amount.as_sat(),
                script_pubkey: script.to_v0_p2wsh(),
            }],
        };

        let mut psbt =
            PartiallySignedTransaction::from_unsigned_tx(unsigned_tx).map_err(Error::from)?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].witness_script = output_metadata.script_pubkey;

        // Set the script witness of the output
        psbt.outputs[0].witness_script = Some(script);

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }

    fn verify_template(&self, lock: script::DataLock<Bitcoin<SegwitV0>>) -> Result<(), FError> {
        (self.psbt.unsigned_tx.version == 2)
            .then(|| 0)
            .ok_or(FError::WrongTemplate("Tx version is not 2"))?;
        (self.psbt.unsigned_tx.lock_time == 0)
            .then(|| 0)
            .ok_or(FError::WrongTemplate("LockTime is not set to 0"))?;
        (self.psbt.unsigned_tx.input.len() == 1)
            .then(|| 0)
            .ok_or(FError::WrongTemplate("Number of inputs is not 1"))?;
        (self.psbt.unsigned_tx.output.len() == 1)
            .then(|| 0)
            .ok_or(FError::WrongTemplate("Number of outputs is not 1"))?;

        let txin = &self.psbt.unsigned_tx.input[0];
        (txin.sequence == CSVTimelock::disable())
            .then(|| 0)
            .ok_or(FError::WrongTemplate("Sequence timelock is not disabled"))?;

        let txout = &self.psbt.unsigned_tx.output[0];
        let script_pubkey = CoopLock::v0_p2wsh(lock);
        (txout.script_pubkey == script_pubkey)
            .then(|| 0)
            .ok_or(FError::WrongTemplate("Script pubkey does not match"))?;

        Ok(())
    }
}
