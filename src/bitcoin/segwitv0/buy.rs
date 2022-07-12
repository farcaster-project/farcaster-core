use std::marker::PhantomData;

use bitcoin::blockdata::transaction::{TxIn, TxOut};
use bitcoin::blockdata::witness::Witness;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::ecdsa::EcdsaSig;
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::Transaction;

use crate::role::SwapRole;
use crate::script;
use crate::transaction::{Buyable, Error as FError, Lockable};

use crate::bitcoin::segwitv0::CoopLock;
use crate::bitcoin::segwitv0::Sha256dHash;
use crate::bitcoin::timelock::CSVTimelock;
use crate::bitcoin::transaction::{Error, MetadataOutput, SubTransaction, Tx};

#[derive(Debug)]
pub struct Buy;

impl SubTransaction for Buy {
    fn finalize(psbt: &mut PartiallySignedTransaction) -> Result<(), FError> {
        let script = psbt.inputs[0]
            .witness_script
            .clone()
            .ok_or(FError::MissingWitness)?;

        let swaplock = CoopLock::from_script(&script)?;

        let alice_sig = *psbt.inputs[0]
            .partial_sigs
            .get(&bitcoin::PublicKey::new(
                *swaplock.get_pubkey(SwapRole::Alice),
            ))
            .ok_or(FError::MissingSignature)?;

        let bob_sig = *psbt.inputs[0]
            .partial_sigs
            .get(&bitcoin::PublicKey::new(
                *swaplock.get_pubkey(SwapRole::Bob),
            ))
            .ok_or(FError::MissingSignature)?;

        psbt.inputs[0].final_script_witness = Some(Witness::from_vec(vec![
            bob_sig.to_vec(),
            alice_sig.to_vec(),
            script.into_bytes(),
        ]));

        Ok(())
    }
}

impl
    Buyable<
        Address,
        Transaction,
        PartiallySignedTransaction,
        MetadataOutput,
        Amount,
        CSVTimelock,
        Sha256dHash,
        PublicKey,
        Signature,
    > for Tx<Buy>
{
    fn initialize(
        prev: &impl Lockable<
            Address,
            Transaction,
            PartiallySignedTransaction,
            MetadataOutput,
            Amount,
            CSVTimelock,
            Sha256dHash,
            PublicKey,
            Signature,
        >,
        _lock: script::DataLock<CSVTimelock, PublicKey>,
        destination_target: Address,
    ) -> Result<Self, FError> {
        let output_metadata = prev.get_consumable_output()?;

        let unsigned_tx = bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: output_metadata.out_point,
                script_sig: bitcoin::Script::default(),
                sequence: 0,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: output_metadata.tx_out.value,
                script_pubkey: destination_target.script_pubkey(),
            }],
        };

        let mut psbt =
            PartiallySignedTransaction::from_unsigned_tx(unsigned_tx).map_err(Error::from)?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].witness_script = output_metadata.script_pubkey;

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }

    fn verify_template(&self, destination_target: Address) -> Result<(), FError> {
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
        (txin.sequence == 0)
            .then(|| 0)
            .ok_or(FError::WrongTemplate("Sequence is not set to 0"))?;

        let txout = &self.psbt.unsigned_tx.output[0];
        let script_pubkey = destination_target.script_pubkey();
        (txout.script_pubkey == script_pubkey)
            .then(|| 0)
            .ok_or(FError::WrongTemplate("Script pubkey does not match"))?;

        Ok(())
    }

    fn extract_witness(tx: bitcoin::Transaction) -> Signature {
        let TxIn { witness, .. } = &tx.input[0];
        let witness_bytes = witness.to_vec();
        let ecdsa_sig = EcdsaSig::from_slice(witness_bytes[0].as_ref())
            .expect("Validated transaction on-chain, signature and witness position is correct.");
        ecdsa_sig.sig
    }
}
