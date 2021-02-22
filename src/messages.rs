//! Protocol messages exchanged between swap daemons
use crate::roles::{Accordant, Arbitrating};

use bitcoin::hash_types::PubkeyHash;
use monero::cryptonote::hash::Hash;

use crate::roles::{Alice, Bob};

pub trait ProtocolMessage {}

// TODO derive protocol message from daemon session

pub struct CommitAliceSessionParams<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    pub buy: Ar::Commitment,
    pub cancel: Ar::Commitment,
    pub refund: Ar::Commitment,
    pub punish: Ar::Commitment,
    pub adaptor: Ar::Commitment,
    pub spend: Ac::Commitment,
    pub view: Ac::Commitment,
}

pub struct CommitBobSessionParams<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    pub buy: Ar::Commitment,
    pub cancel: Ar::Commitment,
    pub refund: Ar::Commitment,
    pub adaptor: Ar::Commitment,
    pub spend: Ac::Commitment,
    pub view: Ac::Commitment,
}

pub struct RevealAliceSessionParams<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    pub buy: Ar::PublicKey,
    pub cancel: Ar::PublicKey,
    pub refund: Ar::PublicKey,
    pub punish: Ar::PublicKey,
    pub adaptor: Ar::PublicKey,
    pub address: Ar::Address,
    pub spend: Ac::PublicKey,
    pub view: Ac::PrivateKey,
    pub proof: Option<String>,
}

pub struct RevealBobSessionParams<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    pub buy: Ar::PublicKey,
    pub cancel: Ar::PublicKey,
    pub refund: Ar::PublicKey,
    pub adaptor: Ar::PublicKey,
    pub address: Ar::Address,
    pub spend: Ac::PublicKey,
    pub view: Ac::PrivateKey,
    pub proof: Option<String>,
}

pub struct CoreArbitratingSetup<Ar>
where
    Ar: Arbitrating,
{
    pub lock: Ar::Transaction,
    pub cancel: Ar::Transaction,
    pub refund: Ar::Transaction,
    pub cancel_sig: Ar::Signature,
}

pub struct RefundProcedureSignatures<Ar>
where
    Ar: Arbitrating,
{
    pub cancel_sig: Ar::Signature,
    pub refund_adaptor_sig: Ar::Signature,
}

pub struct BuyProcedureSignature<Ar>
where
    Ar: Arbitrating,
{
    pub buy: Ar::Transaction,
    pub buy_adaptor_sig: Ar::Signature,
}
