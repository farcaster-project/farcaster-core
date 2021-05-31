use bitcoin::util::psbt::PartiallySignedTransaction;

use crate::script;
use crate::transaction::{Cancelable, Error, Punishable};

use crate::chain::bitcoin::transaction::{MetadataOutput, SubTransaction, Tx};
use crate::chain::bitcoin::{Address, Bitcoin};

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
