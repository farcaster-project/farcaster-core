use std::marker::PhantomData;

use bitcoin::blockdata::transaction::{TxIn, TxOut};
use bitcoin::blockdata::witness::Witness;
use bitcoin::secp256k1::rand::thread_rng;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::{Amount, KeyPair, XOnlyPublicKey};

use crate::script;
use crate::transaction::{Error as FError, Fundable, Lockable};

use crate::bitcoin::taproot::Taproot;
use crate::bitcoin::timelock::CSVTimelock;
use crate::bitcoin::transaction::{Error, MetadataOutput, SubTransaction, Tx};
use crate::bitcoin::Bitcoin;
use bitcoin::util::taproot::TaprootBuilder;

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

impl Lockable<Bitcoin<Taproot>, MetadataOutput> for Tx<Lock> {
    fn initialize(
        prev: &impl Fundable<Bitcoin<Taproot>, MetadataOutput>,
        _lock: script::DataLock<Bitcoin<Taproot>>,
        target_amount: Amount,
    ) -> Result<Self, FError> {
        let secp = Secp256k1::new();
        // FIXME: for a no key spend taproot tx choose a non-spendable internal key and not a
        // random one as follow
        let untweaked_public_key =
            XOnlyPublicKey::from_keypair(&KeyPair::new(&secp, &mut thread_rng()));
        let spend_info = TaprootBuilder::new()
            // FIXME add script path for by and cancel
            .finalize(&secp, untweaked_public_key)
            .expect("Valid taproot FIXME");
        let tweaked_pubkey = spend_info.output_key();
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
                script_pubkey: bitcoin::Script::new_v1_p2tr_tweaked(tweaked_pubkey),
            }],
        };

        let mut psbt =
            PartiallySignedTransaction::from_unsigned_tx(unsigned_tx).map_err(Error::from)?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].witness_script = output_metadata.script_pubkey;

        // FIXME: add tap scripts in PSBT

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }

    fn verify_template(&self, _lock: script::DataLock<Bitcoin<Taproot>>) -> Result<(), FError> {
        todo!()
    }
}
