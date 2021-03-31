use std::marker::PhantomData;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::transaction::{SigHashType, TxIn, TxOut};
use bitcoin::secp256k1::{Secp256k1, Signature};
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::PartiallySignedTransaction;

use farcaster_core::blockchain::{Fee, FeePolitic, FeeStrategy};
use farcaster_core::script;
use farcaster_core::transaction::{Fundable, Lockable, Signable};

use crate::bitcoin::fee::SatPerVByte;
use crate::bitcoin::transaction::{sign_input, Error, MetadataOutput, SubTransaction, Tx, TxInRef};
use crate::bitcoin::Bitcoin;

#[derive(Debug)]
pub struct Lock;

impl SubTransaction for Lock {
    fn finalize(psbt: &mut PartiallySignedTransaction) -> Result<(), Error> {
        let (pubkey, full_sig) = psbt.inputs[0]
            .partial_sigs
            .iter()
            .next()
            .ok_or(Error::MissingSignature)?;
        psbt.inputs[0].final_script_witness = Some(vec![full_sig.clone(), pubkey.to_bytes()]);
        Ok(())
    }
}

impl Lockable<Bitcoin> for Tx<Lock> {
    /// Type returned by the impl of a Funding tx
    type Input = MetadataOutput;

    fn initialize(
        prev: &impl Fundable<Bitcoin, Output = MetadataOutput, Error = Error>,
        lock: script::DataLock<Bitcoin>,
        fee_strategy: &FeeStrategy<SatPerVByte>,
        fee_politic: FeePolitic,
    ) -> Result<Self, Error> {
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
                value: output_metadata.tx_out.value,
                script_pubkey: script.to_v0_p2wsh(),
            }],
        };

        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(unsigned_tx)?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].witness_script = output_metadata.script_pubkey;
        psbt.inputs[0].sighash_type = Some(SigHashType::All);

        // Set the script witness of the output
        psbt.outputs[0].witness_script = Some(script);

        // Set the fees according to the given strategy
        Bitcoin::set_fees(&mut psbt, fee_strategy, fee_politic)?;

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }
}

impl Signable<Bitcoin> for Tx<Lock> {
    fn generate_witness(&mut self, privkey: &PrivateKey) -> Result<Signature, Error> {
        {
            // TODO validate the transaction before signing
        }

        let mut secp = Secp256k1::new();

        let unsigned_tx = self.psbt.global.unsigned_tx.clone();
        let txin = TxInRef::new(&unsigned_tx, 0);

        let witness_utxo = self.psbt.inputs[0]
            .witness_utxo
            .clone()
            .ok_or(Error::MissingWitnessUTXO)?;

        let script = self.psbt.inputs[0]
            .witness_script
            .clone()
            .ok_or(Error::MissingWitnessScript)?;
        let value = witness_utxo.value;

        let sighash_type = self.psbt.inputs[0]
            .sighash_type
            .ok_or(Error::MissingSigHashType)?;

        let sig = sign_input(&mut secp, txin, &script, value, sighash_type, &privkey.key)?;

        // Finalize the witness
        let mut full_sig = sig.serialize_der().to_vec();
        full_sig.extend_from_slice(&[sighash_type.as_u32() as u8]);

        let pubkey = PublicKey::from_private_key(&secp, &privkey);
        self.psbt.inputs[0].partial_sigs.insert(pubkey, full_sig);

        Ok(sig)
    }

    fn verify_witness(&mut self, _pubkey: &PublicKey, _sig: Signature) -> Result<(), Error> {
        todo!()
    }
}
