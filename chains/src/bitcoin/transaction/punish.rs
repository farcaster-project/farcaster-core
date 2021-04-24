use bitcoin::secp256k1::Signature;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::PartiallySignedTransaction;

use farcaster_core::script;
use farcaster_core::transaction::{Cancelable, Error, Forkable, Punishable};

use crate::bitcoin::transaction::{MetadataOutput, SubTransaction, Tx};
use crate::bitcoin::{Address, Bitcoin};

#[derive(Debug)]
pub struct Punish;

impl SubTransaction for Punish {
    fn finalize(_psbt: &mut PartiallySignedTransaction) -> Result<(), Error> {
        todo!()
    }
}

impl Punishable<Bitcoin, MetadataOutput> for Tx<Punish> {
    fn initialize(
        _prev: &impl Cancelable<Bitcoin, MetadataOutput>,
        _punish_lock: script::DataPunishableLock<Bitcoin>,
        _destination_target: Address,
    ) -> Result<Self, Error> {
        todo!()
    }
}

impl Forkable<Bitcoin> for Tx<Punish> {
    fn generate_failure_witness(&self, _privkey: &PrivateKey) -> Result<Signature, Error> {
        todo!()
    }

    fn verify_failure_witness(&self, _pubkey: &PublicKey, _sig: Signature) -> Result<(), Error> {
        todo!()
    }
}
