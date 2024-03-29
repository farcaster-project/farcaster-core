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
use crate::script::ScriptPath;
use crate::transaction::{Cancelable, Error, Punishable};

use crate::bitcoin::segwitv0::PunishLock;
use crate::bitcoin::segwitv0::Sha256dHash;
use crate::bitcoin::timelock::CSVTimelock;
use crate::bitcoin::transaction::{self, MetadataOutput, SubTransaction, Tx};

#[derive(Debug)]
pub struct Punish;

impl SubTransaction for Punish {
    fn finalize(psbt: &mut PartiallySignedTransaction) -> Result<(), Error> {
        let script = psbt.inputs[0]
            .witness_script
            .clone()
            .ok_or(Error::MissingWitness)?;

        let swaplock = PunishLock::from_script(&script)?;

        let punish_sig = *psbt.inputs[0]
            .partial_sigs
            .get(&bitcoin::PublicKey::new(
                *swaplock
                    .get_pubkey(SwapRole::Alice, ScriptPath::Success)
                    .ok_or(Error::MissingPublicKey)?,
            ))
            .ok_or(Error::MissingSignature)?;

        psbt.inputs[0].final_script_witness = Some(Witness::from_vec(vec![
            punish_sig.to_vec(),
            vec![], // OP_FALSE
            script.into_bytes(),
        ]));
        Ok(())
    }
}

impl
    Punishable<
        Address,
        Transaction,
        PartiallySignedTransaction,
        MetadataOutput,
        Amount,
        CSVTimelock,
        Sha256dHash,
        PublicKey,
        Signature,
    > for Tx<Punish>
{
    fn initialize(
        prev: &impl Cancelable<
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
        punish_lock: script::DataPunishableLock<CSVTimelock, PublicKey>,
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
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: output_metadata.tx_out.value,
                script_pubkey: destination_target.script_pubkey(),
            }],
        };

        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(unsigned_tx)
            .map_err(transaction::Error::from)?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].witness_script = output_metadata.script_pubkey;

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }
}
