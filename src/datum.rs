use crate::blockchain::{Fee, FeeStrategy};
use crate::crypto::{self, Crypto, CryptoEngine, Signatures};
use crate::role::{Accordant, Arbitrating, SwapRole};

pub trait Datum {}

pub struct Transaction<Ar>
where
    Ar: Arbitrating,
{
    pub tx_id: TxId,
    pub tx_value: Ar::Transaction,
}

// TODO(h4sh3d): move this into transaction:: module
pub enum TxId {
    Funding,
    Lock,
    Buy,
    Cancel,
    Refund,
    Publish,
}

pub struct Key<Ar, Ac>
where
    Ar: Crypto,
    Ac: Crypto,
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

pub struct Proof<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    pub proof: crypto::Proof<Ar, Ac>,
}

pub enum Parameter<Ar, S>
where
    Ar: Arbitrating + Fee,
    S: FeeStrategy,
{
    DestinationAddress(Ar::Address),
    RefundAddress(Ar::Address),
    CancelTimelock(Ar::Timelock),
    PunishTimelock(Ar::Timelock),
    FeeStrategy(S),
}
