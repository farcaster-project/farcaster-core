// Copyright 2021-2022 Farcaster Devs
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

use std::marker::PhantomData;

use bitcoin::blockdata::transaction::{TxIn, TxOut};
use bitcoin::blockdata::witness::Witness;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::Transaction;

use crate::role::SwapRole;
use crate::script;
use crate::transaction::{Cancelable, Error as FError, Lockable};

use crate::bitcoin::segwitv0::Sha256dHash;
use crate::bitcoin::segwitv0::{CoopLock, PunishLock};
use crate::bitcoin::timelock::CSVTimelock;
use crate::bitcoin::transaction::{Error, MetadataOutput, SubTransaction, Tx};

#[derive(Debug)]
pub struct Cancel;

impl SubTransaction for Cancel {
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
    Cancelable<
        Address,
        Transaction,
        PartiallySignedTransaction,
        MetadataOutput,
        Amount,
        CSVTimelock,
        Sha256dHash,
        PublicKey,
        Signature,
    > for Tx<Cancel>
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
        lock: script::DataLock<CSVTimelock, PublicKey>,
        punish_lock: script::DataPunishableLock<CSVTimelock, PublicKey>,
    ) -> Result<Self, FError> {
        let script = PunishLock::script(punish_lock);
        let output_metadata = prev.get_consumable_output()?;

        let unsigned_tx = bitcoin::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: output_metadata.out_point,
                script_sig: bitcoin::Script::default(),
                sequence: lock.timelock.as_u32(),
                witness: Witness::new(),
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

        // Set the script witness of the output
        psbt.outputs[0].witness_script = Some(script);

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }

    fn verify_template(
        &self,
        lock: script::DataLock<CSVTimelock, PublicKey>,
        punish_lock: script::DataPunishableLock<CSVTimelock, PublicKey>,
    ) -> Result<(), FError> {
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
        (txin.sequence == lock.timelock.as_u32())
            .then(|| 0)
            .ok_or(FError::WrongTemplate(
                "Sequence is not set correctly for timelock",
            ))?;

        let txout = &self.psbt.unsigned_tx.output[0];
        let script_pubkey = PunishLock::v0_p2wsh(punish_lock);
        (txout.script_pubkey == script_pubkey)
            .then(|| 0)
            .ok_or(FError::WrongTemplate("Script pubkey does not match"))?;

        Ok(())
    }
}
