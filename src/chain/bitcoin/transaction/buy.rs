use std::marker::PhantomData;

use bitcoin::blockdata::script::Instruction;
use bitcoin::blockdata::transaction::{SigHashType, TxIn, TxOut};
use bitcoin::util::key::PublicKey;
use bitcoin::util::psbt::PartiallySignedTransaction;

use crate::script;
use crate::transaction::{Buyable, Error as FError, Lockable};

use crate::chain::bitcoin::transaction::{Error, MetadataOutput, SubTransaction, Tx};
use crate::chain::bitcoin::{Address, Bitcoin};

#[derive(Debug)]
pub struct Buy;

impl SubTransaction for Buy {
    fn finalize(psbt: &mut PartiallySignedTransaction) -> Result<(), FError> {
        let script = psbt.inputs[0]
            .witness_script
            .clone()
            .ok_or(FError::MissingWitness)?;

        let mut keys = script.instructions().skip(2).take(2);

        psbt.inputs[0].final_script_witness = Some(vec![
            vec![], // 0 for multisig
            psbt.inputs[0]
                .partial_sigs
                .get(
                    &PublicKey::from_slice(
                        keys.next()
                            .ok_or(FError::MissingPublicKey)?
                            .map(|i| match i {
                                Instruction::PushBytes(b) => Ok(b),
                                _ => Err(FError::MissingPublicKey),
                            })
                            .map_err(Error::from)??,
                    )
                    .map_err(|_| FError::MissingPublicKey)?,
                )
                .ok_or(FError::MissingSignature)?
                .clone(),
            psbt.inputs[0]
                .partial_sigs
                .get(
                    &PublicKey::from_slice(
                        keys.next()
                            .ok_or(FError::MissingPublicKey)?
                            .map(|i| match i {
                                Instruction::PushBytes(b) => Ok(b),
                                _ => Err(FError::MissingPublicKey),
                            })
                            .map_err(Error::from)??,
                    )
                    .map_err(|_| FError::MissingPublicKey)?,
                )
                .ok_or(FError::MissingSignature)?
                .clone(),
            vec![1],             // OP_TRUE
            script.into_bytes(), // swaplock script
        ]);

        Ok(())
    }
}

impl Buyable<Bitcoin, MetadataOutput> for Tx<Buy> {
    fn initialize(
        prev: &impl Lockable<Bitcoin, MetadataOutput>,
        _lock: script::DataLock<Bitcoin>,
        destination_target: Address,
    ) -> Result<Self, FError> {
        let output_metadata = prev.get_consumable_output()?;

        let unsigned_tx = bitcoin::blockdata::transaction::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: output_metadata.out_point,
                script_sig: bitcoin::blockdata::script::Script::default(),
                sequence: 0,
                witness: vec![],
            }],
            output: vec![TxOut {
                value: output_metadata.tx_out.value,
                script_pubkey: destination_target.0.script_pubkey(),
            }],
        };

        let mut psbt =
            PartiallySignedTransaction::from_unsigned_tx(unsigned_tx).map_err(Error::from)?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].witness_script = output_metadata.script_pubkey;
        psbt.inputs[0].sighash_type = Some(SigHashType::All);

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }

    fn verify_template(
        &self,
        _lock: script::DataLock<Bitcoin>,
        _destination_target: Address,
    ) -> Result<(), FError> {
        // FIXME
        Ok(())
    }
}
