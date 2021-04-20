use bitcoin::blockdata::script::Instruction;
use bitcoin::secp256k1::Signature;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::PartiallySignedTransaction;

use farcaster_core::script;
use farcaster_core::transaction::{AdaptorSignable, Buyable, Error as FError, Lockable, Signable};

use crate::bitcoin::transaction::{Error, MetadataOutput, SubTransaction, Tx};
use crate::bitcoin::{Address, Bitcoin, ECDSAAdaptorSig};

#[derive(Debug)]
pub struct Buy;

impl SubTransaction for Buy {
    fn finalize(psbt: &mut PartiallySignedTransaction) -> Result<(), FError> {
        let script = psbt.inputs[0]
            .witness_script
            .clone()
            .ok_or(FError::MissingWitness)?;

        let mut keys = script.instructions().skip(2).take(2);

        psbt.inputs[0].final_script_witness = Some(vec![
            vec![], // 0 for multisig
            psbt.inputs[0]
                .partial_sigs
                .get(
                    &PublicKey::from_slice(
                        keys.next()
                            .ok_or(FError::MissingPublicKey)?
                            .map(|i| match i {
                                Instruction::PushBytes(b) => Ok(b),
                                _ => Err(FError::MissingPublicKey),
                            })
                            .map_err(Error::from)??,
                    )
                    .map_err(|_| FError::MissingPublicKey)?,
                )
                .ok_or(FError::MissingSignature)?
                .clone(),
            psbt.inputs[0]
                .partial_sigs
                .get(
                    &PublicKey::from_slice(
                        keys.next()
                            .ok_or(FError::MissingPublicKey)?
                            .map(|i| match i {
                                Instruction::PushBytes(b) => Ok(b),
                                _ => Err(FError::MissingPublicKey),
                            })
                            .map_err(Error::from)??,
                    )
                    .map_err(|_| FError::MissingPublicKey)?,
                )
                .ok_or(FError::MissingSignature)?
                .clone(),
            vec![1],             // OP_TRUE
            script.into_bytes(), // swaplock script
        ]);

        Ok(())
    }
}

impl Buyable<Bitcoin, MetadataOutput> for Tx<Buy> {
    fn initialize(
        _prev: &impl Lockable<Bitcoin, MetadataOutput>,
        _lock: script::DataLock<Bitcoin>,
        _destination_target: Address,
    ) -> Result<Self, FError> {
        todo!()
    }
}

impl Signable<Bitcoin> for Tx<Buy> {
    fn generate_witness(&self, _privkey: &PrivateKey) -> Result<Signature, FError> {
        {
            // TODO validate the transaction before signing
        }
        todo!()
    }

    fn verify_witness(&self, _pubkey: &PublicKey, _sig: Signature) -> Result<(), FError> {
        todo!()
    }
}

impl AdaptorSignable<Bitcoin> for Tx<Buy> {
    fn generate_adaptor_witness(
        &self,
        _privkey: &PrivateKey,
        _adaptor: &PublicKey,
    ) -> Result<ECDSAAdaptorSig, FError> {
        todo!()
    }

    fn verify_adaptor_witness(
        &self,
        _pubkey: &PublicKey,
        _adaptor: &PublicKey,
        _sig: ECDSAAdaptorSig,
    ) -> Result<(), FError> {
        todo!()
    }
}
