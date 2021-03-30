use crate::blockchain::{Fee, FeeStrategy};
use crate::crypto::{self, Keys, Signatures};
use crate::role::{Arbitrating, SwapRole};
use crate::transaction::TxId;

pub trait Datum {}

pub struct Transaction<Ar>
where
    Ar: Arbitrating,
{
    pub tx_id: TxId,
    pub tx_value: Ar::Transaction,
}

pub struct Key<Ar, Ac>
where
    Ar: Keys,
    Ac: Keys,
{
    pub key: crypto::Key<Ar, Ac>,
}

pub struct Signature<Ar>
where
    Ar: Signatures,
{
    pub tx_id: TxId,
    pub role: SwapRole,
    pub value: crypto::Signature<Ar>,
}

pub use crate::crypto::Proof;
// use strict_encoding::{StrictEncode, StrictDecode};
// #[derive(Clone, Debug, StrictDecode, StrictEncode)]
// #[strict_encoding_crate(strict_encoding)]
// pub struct Proof<Ar, Ac>
// where
//     Ar: Curve + Clone,
//     Ac: Curve + Clone,
// {
//     pub proof: crypto::InnerProof<Ar, Ac>,
// }

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
