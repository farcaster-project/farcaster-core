use bitcoin::blockdata::script::Instruction;
use bitcoin::secp256k1::Signature;
use bitcoin::util::address::Address;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::PartiallySignedTransaction;

use farcaster_core::blockchain::{FeePolitic, FeeStrategy};
use farcaster_core::script;
use farcaster_core::transaction::{AdaptorSignable, Buyable, Cooperable, Lockable, Signable};

use crate::bitcoin::fee::SatPerVByte;
use crate::bitcoin::transaction::{Error, MetadataOutput, SubTransaction, Tx};
use crate::bitcoin::{Bitcoin, ECDSAAdaptorSig};

#[derive(Debug)]
pub struct Buy;

impl SubTransaction for Buy {
    fn finalize(psbt: &mut PartiallySignedTransaction) -> Result<(), Error> {
        let script = psbt.inputs[0]
            .witness_script
            .clone()
            .ok_or(Error::MissingWitnessScript)?;

        let mut keys = script.instructions().skip(2).take(2);

        psbt.inputs[0].final_script_witness = Some(vec![
            vec![], // 0 for multisig
            psbt.inputs[0]
                .partial_sigs
                .get(
                    &PublicKey::from_slice(keys.next().ok_or(Error::PublicKeyNotFound)?.map(
                        |i| match i {
                            Instruction::PushBytes(b) => Ok(b),
                            _ => Err(Error::PublicKeyNotFound),
                        },
                    )??)
                    .map_err(|_| Error::PublicKeyNotFound)?,
                )
                .ok_or(Error::MissingSignature)?
                .clone(),
            psbt.inputs[0]
                .partial_sigs
                .get(
                    &PublicKey::from_slice(keys.next().ok_or(Error::PublicKeyNotFound)?.map(
                        |i| match i {
                            Instruction::PushBytes(b) => Ok(b),
                            _ => Err(Error::PublicKeyNotFound),
                        },
                    )??)
                    .map_err(|_| Error::PublicKeyNotFound)?,
                )
                .ok_or(Error::MissingSignature)?
                .clone(),
            vec![1],             // OP_TRUE
            script.into_bytes(), // swaplock script
        ]);

        Ok(())
    }
}

impl Buyable<Bitcoin> for Tx<Buy> {
    /// Type returned by the impl of a Lock tx
    type Input = MetadataOutput;

    fn initialize(
        _prev: &impl Lockable<Bitcoin, Output = MetadataOutput>,
        _lock: script::DataLock<Bitcoin>,
        _destination_target: Address,
        _fee_strategy: &FeeStrategy<SatPerVByte>,
        _fee_politic: FeePolitic,
    ) -> Result<Self, Error> {
        todo!()
    }
}

impl Signable<Bitcoin> for Tx<Buy> {
    fn generate_witness(&mut self, _privkey: &PrivateKey) -> Result<Signature, Error> {
        {
            // TODO validate the transaction before signing
        }
        todo!()
    }

    fn verify_witness(&mut self, _pubkey: &PublicKey, _sig: Signature) -> Result<(), Error> {
        todo!()
    }
}

impl AdaptorSignable<Bitcoin> for Tx<Buy> {
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

impl Cooperable<Bitcoin> for Tx<Buy> {
    fn add_cooperation(&mut self, pubkey: PublicKey, sig: Signature) -> Result<(), Error> {
        let sighash_type = self.psbt.inputs[0]
            .sighash_type
            .ok_or(Error::MissingSigHashType)?;
        let mut full_sig = sig.serialize_der().to_vec();
        full_sig.extend_from_slice(&[sighash_type.as_u32() as u8]);
        self.psbt.inputs[0].partial_sigs.insert(pubkey, full_sig);
        Ok(())
    }
}
