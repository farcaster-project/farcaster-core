use std::marker::PhantomData;

use bitcoin::blockdata::transaction::{SigHashType, TxIn, TxOut};
use bitcoin::secp256k1::Signature;
use bitcoin::util::address::Address;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::PartiallySignedTransaction;

use farcaster_core::blockchain::{Fee, FeePolitic, FeeStrategy};
use farcaster_core::script;
use farcaster_core::transaction::{AdaptorSignable, Cancelable, Cooperable, Refundable, Signable};

use crate::bitcoin::fee::SatPerVByte;
use crate::bitcoin::transaction::{Error, MetadataOutput, SubTransaction, Tx};
use crate::bitcoin::{Bitcoin, ECDSAAdaptorSig};

#[derive(Debug)]
pub struct Refund;

impl SubTransaction for Refund {}

impl Refundable<Bitcoin> for Tx<Refund> {
    /// Type returned by the impl of a Lock tx
    type Input = MetadataOutput;

    fn initialize(
        prev: &impl Cancelable<Bitcoin, Output = MetadataOutput, Error = Error>,
        punish_lock: script::DataPunishableLock<Bitcoin>,
        refund_target: Address,
        fee_strategy: &FeeStrategy<SatPerVByte>,
        fee_politic: FeePolitic,
    ) -> Result<Self, Error> {
        let output_metadata = prev.get_consumable_output()?;

        let unsigned_tx = bitcoin::blockdata::transaction::Transaction {
            version: 2,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: output_metadata.out_point,
                script_sig: bitcoin::blockdata::script::Script::default(),
                sequence: punish_lock.timelock.as_u32(),
                witness: vec![],
            }],
            output: vec![TxOut {
                value: output_metadata.tx_out.value,
                script_pubkey: refund_target.script_pubkey(),
            }],
        };

        let mut psbt = PartiallySignedTransaction::from_unsigned_tx(unsigned_tx)?;

        // Set the input witness data and sighash type
        psbt.inputs[0].witness_utxo = Some(output_metadata.tx_out);
        psbt.inputs[0].sighash_type = Some(SigHashType::All);

        // Set the fees according to the given strategy
        Bitcoin::set_fees(&mut psbt, fee_strategy, fee_politic)?;

        Ok(Tx {
            psbt,
            _t: PhantomData,
        })
    }
}

impl Signable<Bitcoin> for Tx<Refund> {
    fn generate_witness(&mut self, _privkey: &PrivateKey) -> Result<Signature, Error> {
        todo!()
    }

    fn verify_witness(&mut self, _pubkey: &PublicKey, _sig: Signature) -> Result<(), Error> {
        todo!()
    }
}

impl AdaptorSignable<Bitcoin> for Tx<Refund> {
    fn generate_adaptor_witness(
        &mut self,
        _privkey: &PrivateKey,
        _adaptor: &PublicKey,
    ) -> Result<ECDSAAdaptorSig, Error> {
        todo!()
    }

    fn verify_adaptor_witness(
        &mut self,
        _pubkey: &PublicKey,
        _adaptor: &PublicKey,
        _sig: ECDSAAdaptorSig,
    ) -> Result<(), Error> {
        todo!()
    }
}

impl Cooperable<Bitcoin> for Tx<Refund> {
    fn add_cooperation(&mut self, pubkey: PublicKey, sig: Signature) -> Result<(), Error> {
        let sighash_type = self.psbt.inputs[0]
            .sighash_type
            .ok_or(Error::MissingSigHashType)?;
        let mut full_sig = sig.serialize_der().to_vec();
        full_sig.extend_from_slice(&[sighash_type.as_u32() as u8]);
        self.psbt.inputs[0].partial_sigs.insert(pubkey, full_sig);
        Ok(())
    }

    fn finalize(&mut self) -> Result<(), Error> {
        todo!()
    }
}
