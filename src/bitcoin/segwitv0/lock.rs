use std::marker::PhantomData;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::transaction::{SigHashType, TxIn, TxOut};
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::Amount;

use crate::script;
use crate::transaction::{Error as FError, Fundable, Lockable};

use crate::bitcoin::segwitv0::SegwitV0;
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
        psbt.inputs[0].final_script_witness = Some(vec![full_sig.clone(), pubkey.to_bytes()]);
        Ok(())
    }
}

impl Lockable<Bitcoin<SegwitV0>, MetadataOutput> for Tx<Lock> {
    fn initialize(
        prev: &impl Fundable<Bitcoin<SegwitV0>, MetadataOutput>,
        lock: script::DataLock<Bitcoin<SegwitV0>>,
        target_amount: Amount,
    ) -> Result<Self, FError> {
        let script = Builder::new()
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&bitcoin::util::ecdsa::PublicKey::new(lock.success.alice))
            .push_key(&bitcoin::util::ecdsa::PublicKey::new(lock.success.bob))
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_int(lock.timelock.as_u32().into())
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&bitcoin::util::ecdsa::PublicKey::new(lock.failure.alice))
            .push_key(&bitcoin::util::ecdsa::PublicKey::new(lock.failure.bob))
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();

        let output_metadata = prev.get_consumable_output()?;

        if output_metadata.tx_out.value < target_amount.as_sat() {
            return Err(FError::NotEnoughAssets);
        }

        let unsigned_tx = bitcoin::blockdata::transaction::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: output_metadata.out_point,
                script_sig: bitcoin::blockdata::script::Script::default(),
                sequence: (1 << 31) as u32, // activate disable flag on CSV
                witness: vec![],
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
        psbt.inputs[0].sighash_type = Some(SigHashType::All);

        // Set the script witness of the output
        psbt.outputs[0].witness_script = Some(script);

        // TODO move the logic inside core
        //// Set the fees according to the given strategy
        //Bitcoin::set_fees(&mut psbt, fee_strategy, fee_politic)?;

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }

    fn verify_template(&self, lock: script::DataLock<Bitcoin<SegwitV0>>) -> Result<(), FError> {
        (self.psbt.global.unsigned_tx.version == 2)
            .then(|| 0)
            .ok_or(FError::WrongTemplate)?;
        (self.psbt.global.unsigned_tx.lock_time == 0)
            .then(|| 0)
            .ok_or(FError::WrongTemplate)?;
        (self.psbt.global.unsigned_tx.input.len() == 1)
            .then(|| 0)
            .ok_or(FError::WrongTemplate)?;
        (self.psbt.global.unsigned_tx.output.len() == 1)
            .then(|| 0)
            .ok_or(FError::WrongTemplate)?;

        let txin = &self.psbt.global.unsigned_tx.input[0];
        (txin.sequence == (1 << 31) as u32)
            .then(|| 0)
            .ok_or(FError::WrongTemplate)?;

        let txout = &self.psbt.global.unsigned_tx.output[0];
        let script = Builder::new()
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&bitcoin::util::ecdsa::PublicKey::new(lock.success.alice))
            .push_key(&bitcoin::util::ecdsa::PublicKey::new(lock.success.bob))
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_int(lock.timelock.as_u32().into())
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&bitcoin::util::ecdsa::PublicKey::new(lock.failure.alice))
            .push_key(&bitcoin::util::ecdsa::PublicKey::new(lock.failure.bob))
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();
        (txout.script_pubkey == script.to_v0_p2wsh())
            .then(|| 0)
            .ok_or(FError::WrongTemplate)?;

        Ok(())
    }
}
