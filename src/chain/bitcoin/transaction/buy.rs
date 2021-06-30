use bitcoin::blockdata::script::Instruction;
use bitcoin::util::key::PublicKey;
use bitcoin::util::psbt::PartiallySignedTransaction;

use crate::script;
use crate::transaction::{Buyable, Error as FError, Lockable};

use crate::chain::bitcoin::transaction::{Error, MetadataOutput, SubTransaction, Tx};
use crate::chain::bitcoin::{Address, Bitcoin};

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

    fn verify_template(
        &self,
        _lock: script::DataLock<Bitcoin>,
        _destination_target: Address,
    ) -> Result<(), FError> {
        todo!()
    }
}
