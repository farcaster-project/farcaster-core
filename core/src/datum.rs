//! Datum messages exchanged between client and daemon to update their states

use strict_encoding::{StrictDecode, StrictEncode};

use crate::blockchain::{Fee, FeeStrategy};
use crate::crypto::{self, Signatures};
use crate::role::{Arbitrating, SwapRole};
use crate::swap::Swap;
use crate::transaction::TxId;

pub trait Datum {}

#[derive(Debug, Clone)]
pub struct Transaction<Ar>
where
    Ar: Arbitrating,
{
    pub tx_id: TxId,
    pub tx_value: Ar::PartialTransaction,
}

#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct Key<Ctx: Swap> {
    pub key: crypto::Key<Ctx>,
}

impl<Ctx: Swap> From<crypto::Key<Ctx>> for Key<Ctx> {
    fn from(key: crypto::Key<Ctx>) -> Self {
        Key { key }
    }
}

#[derive(Debug, Clone)]
pub struct Signature<Ar>
where
    Ar: Signatures,
{
    pub tx_id: TxId,
    pub role: SwapRole,
    pub value: crypto::SignatureType<Ar>,
}

#[derive(Clone, Debug, StrictDecode, StrictEncode)]
#[strict_encoding_crate(strict_encoding)]
pub struct Proof<Ctx: Swap> {
    pub proof: Ctx::Proof,
}

#[derive(Debug, Clone)]
pub enum Parameter<Ar>
where
    Ar: Arbitrating + Fee,
{
    DestinationAddress(Ar::Address),
    RefundAddress(Ar::Address),
    CancelTimelock(Ar::Timelock),
    PunishTimelock(Ar::Timelock),
    FeeStrategy(FeeStrategy<Ar::FeeUnit>),
}
