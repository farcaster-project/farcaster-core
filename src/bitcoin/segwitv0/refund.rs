use std::marker::PhantomData;

use bitcoin::blockdata::transaction::{SigHashType, TxIn, TxOut};
use bitcoin::secp256k1::Signature;
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::Address;

use crate::role::SwapRole;
use crate::script::ScriptPath;
use crate::transaction::{Cancelable, Error as FError, Refundable};

use crate::bitcoin::segwitv0::{PunishLock, SegwitV0};
use crate::bitcoin::transaction::{Error, MetadataOutput, SubTransaction, Tx};
use crate::bitcoin::Bitcoin;

#[derive(Debug)]
pub struct Refund;

impl SubTransaction for Refund {
    fn finalize(psbt: &mut PartiallySignedTransaction) -> Result<(), FError> {
        let script = psbt.inputs[0]
            .witness_script
            .clone()
            .ok_or(FError::MissingWitness)?;

        let swaplock = PunishLock::from_script(&script)?;

        let alice_sig = psbt.inputs[0]
            .partial_sigs
            .get(
                swaplock
                    .get_pubkey(SwapRole::Alice, ScriptPath::Success)
                    .ok_or(FError::MissingPublicKey)?,
            )
            .ok_or(FError::MissingSignature)?
            .clone();

        let bob_sig = psbt.inputs[0]
            .partial_sigs
            .get(
                swaplock
                    .get_pubkey(SwapRole::Bob, ScriptPath::Success)
                    .ok_or(FError::MissingPublicKey)?,
            )
            .ok_or(FError::MissingSignature)?
            .clone();

        psbt.inputs[0].final_script_witness = Some(vec![
            bob_sig,
            alice_sig,
            vec![1],             // OP_TRUE
            script.into_bytes(), // cancel script
        ]);

        Ok(())
    }
}

impl Refundable<Bitcoin<SegwitV0>, MetadataOutput> for Tx<Refund> {
    fn initialize(
        prev: &impl Cancelable<Bitcoin<SegwitV0>, MetadataOutput>,
        refund_target: Address,
    ) -> Result<Self, FError> {
        let output_metadata = prev.get_consumable_output()?;

        let unsigned_tx = bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: output_metadata.out_point,
                script_sig: bitcoin::Script::default(),
                sequence: 0,
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

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }

    fn verify_template(&self, refund_target: Address) -> Result<(), FError> {
        (self.psbt.global.unsigned_tx.version == 2)
            .then(|| 0)
            .ok_or(FError::WrongTemplate("Tx version is not 2"))?;
        (self.psbt.global.unsigned_tx.lock_time == 0)
            .then(|| 0)
            .ok_or(FError::WrongTemplate("LockTime is not set to 0"))?;
        (self.psbt.global.unsigned_tx.input.len() == 1)
            .then(|| 0)
            .ok_or(FError::WrongTemplate("Number of inputs is not 1"))?;
        (self.psbt.global.unsigned_tx.output.len() == 1)
            .then(|| 0)
            .ok_or(FError::WrongTemplate("Number of outputs is not 1"))?;

        let txin = &self.psbt.global.unsigned_tx.input[0];
        (txin.sequence == 0)
            .then(|| 0)
            .ok_or(FError::WrongTemplate("Sequence is not set to 0"))?;

        let txout = &self.psbt.global.unsigned_tx.output[0];
        let script_pubkey = refund_target.script_pubkey();
        (txout.script_pubkey == script_pubkey)
            .then(|| 0)
            .ok_or(FError::WrongTemplate("Script pubkey does not match"))?;

        Ok(())
    }

    fn extract_witness(tx: bitcoin::Transaction) -> Signature {
        let TxIn { witness, .. } = &tx.input[0];
        let bytes: &[u8] = witness[1].as_ref();
        // Remove SIGHASH type at the end of the signature
        Signature::from_der(&bytes[..bytes.len() - 1])
            .expect("Validated transaction on-chain, signature and witness position is correct.")
    }
}
