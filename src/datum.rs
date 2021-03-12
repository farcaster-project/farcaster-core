use crate::blockchain::{Fee, FeeStrategy};
use crate::crypto::{self, Crypto, CryptoEngine};
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

pub struct Key<Ar, Ac, C>
where
    Ar: Arbitrating + Crypto<C>,
    Ac: Accordant,
    C: CryptoEngine,
{
    pub key: crypto::Key<Ar, Ac, C>,
}

pub struct Signature<Ar, C>
where
    Ar: Arbitrating + Crypto<C>,
    C: CryptoEngine,
{
    pub tx_id: TxId,
    pub role: SwapRole,
    pub value: crypto::Signature<Ar, C>,
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
    Ar: Arbitrating + Fee<S>,
    S: FeeStrategy,
{
    DestinationAddress(Ar::Address),
    RefundAddress(Ar::Address),
    CancelTimelock(Ar::Timelock),
    PunishTimelock(Ar::Timelock),
    FeeStrategy(S),
}
