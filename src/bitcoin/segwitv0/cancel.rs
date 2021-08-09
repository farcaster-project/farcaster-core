use std::marker::PhantomData;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::script::Instruction;
use bitcoin::blockdata::transaction::{SigHashType, TxIn, TxOut};
use bitcoin::util::key::PublicKey;
use bitcoin::util::psbt::PartiallySignedTransaction;

use crate::script;
use crate::transaction::{Cancelable, Error as FError, Lockable};

use crate::bitcoin::segwitv0::SegwitV0;
use crate::bitcoin::transaction::{Error, MetadataOutput, SubTransaction, Tx};
use crate::bitcoin::Bitcoin;

#[derive(Debug)]
pub struct Cancel;

impl SubTransaction for Cancel {
    fn finalize(psbt: &mut PartiallySignedTransaction) -> Result<(), FError> {
        let script = psbt.inputs[0]
            .witness_script
            .clone()
            .ok_or(FError::MissingWitness)?;

        let mut keys = script.instructions().skip(11).take(2);

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
            vec![],              // OP_FALSE
            script.into_bytes(), // swaplock script
        ]);

        Ok(())
    }
}

impl Cancelable<Bitcoin<SegwitV0>, MetadataOutput> for Tx<Cancel> {
    fn initialize(
        prev: &impl Lockable<Bitcoin<SegwitV0>, MetadataOutput>,
        lock: script::DataLock<Bitcoin<SegwitV0>>,
        punish_lock: script::DataPunishableLock<Bitcoin<SegwitV0>>,
    ) -> Result<Self, FError> {
        let script = Builder::new()
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&punish_lock.success.alice)
            .push_key(&punish_lock.success.bob)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_int(punish_lock.timelock.as_u32().into())
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_key(&punish_lock.failure)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();

        let output_metadata = prev.get_consumable_output()?;

        let unsigned_tx = bitcoin::blockdata::transaction::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: output_metadata.out_point,
                script_sig: bitcoin::blockdata::script::Script::default(),
                sequence: lock.timelock.as_u32(),
                witness: vec![],
            }],
            output: vec![TxOut {
                value: output_metadata.tx_out.value,
                script_pubkey: script.to_v0_p2wsh(),
            }],
        };

        let mut psbt =
            PartiallySignedTransaction::from_unsigned_tx(unsigned_tx).map_err(Error::from)?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].witness_script = output_metadata.script_pubkey;
        psbt.inputs[0].sighash_type = Some(SigHashType::All);

        // Set the script witness of the output
        psbt.outputs[0].witness_script = Some(script);

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }

    fn verify_template(
        &self,
        _lock: script::DataLock<Bitcoin<SegwitV0>>,
        _punish_lock: script::DataPunishableLock<Bitcoin<SegwitV0>>,
    ) -> Result<(), FError> {
        // FIXME
        Ok(())
    }
}
