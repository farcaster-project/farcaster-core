use std::marker::PhantomData;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::transaction::{SigHashType, TxIn, TxOut};
use bitcoin::hashes::sha256d::Hash;
use bitcoin::util::psbt::PartiallySignedTransaction;

use farcaster_core::script;
use farcaster_core::transaction::{Error as FError, Fundable, Lockable, Signable};

use crate::bitcoin::transaction::{
    signature_hash, Error, MetadataOutput, SubTransaction, Tx, TxInRef,
};
use crate::bitcoin::{Amount, Bitcoin};

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

impl Lockable<Bitcoin, MetadataOutput> for Tx<Lock> {
    fn initialize(
        prev: &impl Fundable<Bitcoin, MetadataOutput>,
        lock: script::DataLock<Bitcoin>,
        target_amount: Amount,
    ) -> Result<Self, FError> {
        let script = Builder::new()
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&lock.success.alice)
            .push_key(&lock.success.bob)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_int(lock.timelock.as_u32().into())
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&lock.failure.alice)
            .push_key(&lock.failure.bob)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();

        let output_metadata = prev.get_consumable_output()?;

        match output_metadata.tx_out.value < target_amount.as_sat() {
            true => Err(FError::NotEnoughAssets)?,
            false => (),
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

    fn verify_template(&self, lock: script::DataLock<Bitcoin>) -> Result<(), FError> {
        (self.psbt.global.unsigned_tx.version == 2)
            .then(|| 0)
            .ok_or_else(|| FError::WrongTemplate)?;
        (self.psbt.global.unsigned_tx.lock_time == 0)
            .then(|| 0)
            .ok_or_else(|| FError::WrongTemplate)?;
        (self.psbt.global.unsigned_tx.input.len() == 1)
            .then(|| 0)
            .ok_or_else(|| FError::WrongTemplate)?;
        (self.psbt.global.unsigned_tx.output.len() == 1)
            .then(|| 0)
            .ok_or_else(|| FError::WrongTemplate)?;

        let txin = &self.psbt.global.unsigned_tx.input[0];
        (txin.sequence == (1 << 31) as u32)
            .then(|| 0)
            .ok_or_else(|| FError::WrongTemplate)?;

        let txout = &self.psbt.global.unsigned_tx.output[0];
        let script = Builder::new()
            .push_opcode(opcodes::all::OP_IF)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&lock.success.alice)
            .push_key(&lock.success.bob)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ELSE)
            .push_int(lock.timelock.as_u32().into())
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_key(&lock.failure.alice)
            .push_key(&lock.failure.bob)
            .push_opcode(opcodes::all::OP_PUSHNUM_2)
            .push_opcode(opcodes::all::OP_CHECKMULTISIG)
            .push_opcode(opcodes::all::OP_ENDIF)
            .into_script();
        (txout.script_pubkey == script.to_v0_p2wsh())
            .then(|| 0)
            .ok_or_else(|| FError::WrongTemplate)?;

        Ok(())
    }
}

impl Signable<Bitcoin> for Tx<Lock> {
    fn generate_witness_message(&self) -> Result<Hash, FError> {
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
}
