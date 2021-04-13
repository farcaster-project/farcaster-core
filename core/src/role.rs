//! Roles during negotiation and swap phases, blockchain roles, and network definitions.

use std::fmt::Debug;
use std::io;
use std::str::FromStr;

use strict_encoding::{StrictDecode, StrictEncode};

use crate::blockchain::{Asset, Fee, FeePolitic, Onchain};
use crate::bundle::{
    AliceSessionParams, CosignedArbitratingCancel, FullySignedBuy, SignedAdaptorRefund,
    SignedArbitratingPunish,
};
use crate::consensus::{self, Decodable, Encodable};
use crate::crypto::{
    self, AccordantKey, ArbitratingKey, Commitment, DleqProof, FromSeed, Keys, SharedPrivateKeys,
    Signatures,
};
use crate::datum;
use crate::negotiation::PublicOffer;
use crate::swap::Swap;

/// Defines the possible roles during the negotiation phase. Any negotiation role can transition
/// into any swap role when negotiation is done.
pub enum NegotiationRole {
    /// The maker role create the public offer during the negotiation phase and waits for incoming
    /// connections.
    Maker,
    /// The taker role parses public offers and choose to connect to a maker node to start
    /// swapping.
    Taker,
}

impl NegotiationRole {
    /// Return the other role possible in the negotiation phase.
    pub fn other(&self) -> Self {
        match self {
            Self::Maker => Self::Taker,
            Self::Taker => Self::Maker,
        }
    }
}

/// A maker is one that creates and share a public offer and start his daemon in listening mode so
/// one taker can connect and start interacting with him.
pub struct Maker;

/// A taker parses offers and, if interested, connects to the peer registred in the offer.
pub struct Taker;

/// Defines the possible roles during the swap phase. When negotitation is done negotitation role
/// will transition into swap role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapRole {
    /// Alice, the swap role, is the role starting with accordant blockchain assets and exchange
    /// them for arbitrating blockchain assets.
    Alice,
    /// Bob, the swap role, is the role starting with arbitrating blockchain assets and exchange
    /// them for accordant blockchain assets.
    Bob,
}

impl SwapRole {
    /// Return the other role possible in the swap phase.
    pub fn other(&self) -> Self {
        match self {
            Self::Alice => Self::Bob,
            Self::Bob => Self::Alice,
        }
    }
}

impl Encodable for SwapRole {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            SwapRole::Alice => 0x01u8.consensus_encode(writer),
            SwapRole::Bob => 0x02u8.consensus_encode(writer),
        }
    }
}

impl Decodable for SwapRole {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u8 => Ok(SwapRole::Alice),
            0x02u8 => Ok(SwapRole::Bob),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl FromStr for SwapRole {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Alice" => Ok(SwapRole::Alice),
            "Bob" => Ok(SwapRole::Bob),
            _ => Err(consensus::Error::ParseFailed("Bob or Alice valid")),
        }
    }
}

/// Alice, the swap role, is the role starting with accordant blockchain assets and exchange them
/// for arbitrating blockchain assets.
pub struct Alice<Ctx: Swap> {
    /// An arbitrating address where, if successfully executed, the funds exchanged will be sent to
    pub destination_address: <Ctx::Ar as Arbitrating>::Address,
    /// The fee politic to apply during the swap fee calculation
    pub fee_politic: FeePolitic,
}

impl<Ctx> Alice<Ctx>
where
    Ctx: Swap,
{
    pub fn new(
        destination_address: <Ctx::Ar as Arbitrating>::Address,
        fee_politic: FeePolitic,
    ) -> Self {
        Self {
            destination_address,
            fee_politic,
        }
    }

    pub fn session_params(
        &self,
        ar_seed: &<Ctx::Ar as FromSeed<Arb>>::Seed,
        ac_seed: &<Ctx::Ac as FromSeed<Acc>>::Seed,
        public_offer: &PublicOffer<Ctx>,
    ) -> AliceSessionParams<Ctx> {
        let (spend, adaptor, proof) = Ctx::Proof::generate(ac_seed);
        AliceSessionParams {
            buy: crypto::Key::Alice(crypto::AliceKey::Buy(
                <Ctx::Ar as FromSeed<Arb>>::get_pubkey(ar_seed, crypto::ArbitratingKey::Buy),
            ))
            .into(),
            cancel: crypto::Key::Alice(crypto::AliceKey::Cancel(
                <Ctx::Ar as FromSeed<Arb>>::get_pubkey(ar_seed, crypto::ArbitratingKey::Cancel),
            ))
            .into(),
            refund: crypto::Key::Alice(crypto::AliceKey::Refund(
                <Ctx::Ar as FromSeed<Arb>>::get_pubkey(ar_seed, crypto::ArbitratingKey::Refund),
            ))
            .into(),
            punish: crypto::Key::Alice(crypto::AliceKey::Punish(
                <Ctx::Ar as FromSeed<Arb>>::get_pubkey(ar_seed, crypto::ArbitratingKey::Punish),
            ))
            .into(),
            adaptor: crypto::Key::Alice(crypto::AliceKey::Adaptor(adaptor)).into(),
            destination_address: datum::Parameter::DestinationAddress(
                self.destination_address.clone(),
            ),
            view: crypto::Key::Alice(crypto::AliceKey::PrivateView(
                <Ctx::Ac as SharedPrivateKeys<Acc>>::get_shared_privkey(
                    ac_seed,
                    crypto::SharedPrivateKey::View,
                ),
            ))
            .into(),
            spend: crypto::Key::Alice(crypto::AliceKey::Spend(spend)).into(),
            proof: datum::Proof { proof },
            cancel_timelock: datum::Parameter::CancelTimelock(public_offer.offer.cancel_timelock),
            punish_timelock: datum::Parameter::PunishTimelock(public_offer.offer.punish_timelock),
            fee_strategy: datum::Parameter::FeeStrategy(public_offer.offer.fee_strategy.clone()),
        }
    }

    pub fn signed_adaptor_refund(&self) -> SignedAdaptorRefund<Ctx::Ar> {
        todo!()
    }

    pub fn cosign_arbitrating_cancel(&self) -> CosignedArbitratingCancel<Ctx::Ar> {
        todo!()
    }

    pub fn fully_signed_buy(&self) -> FullySignedBuy<Ctx::Ar> {
        todo!()
    }

    pub fn signed_arbitrating_punish(&self) -> SignedArbitratingPunish<Ctx::Ar> {
        todo!()
    }
}

/// Bob, the swap role, is the role starting with arbitrating blockchain assets and exchange them
/// for accordant blockchain assets.
pub struct Bob<Ctx: Swap> {
    /// An arbitrating address where, if unsuccessfully executed, the funds exchanged will be sent
    /// back to
    pub refund_address: <Ctx::Ar as Arbitrating>::Address,
    /// The fee politic to apply during the swap fee calculation
    pub fee_politic: FeePolitic,
}

///// Defines all possible blockchain roles: arbitrating and accordant.
//pub enum BlockchainRole {
//    /// The arbitrating blockchain is used to conduct the swap as a decision engine and to
//    /// guarentee the refund process.
//    Arbitrating,
//    /// The accordant blockchain is the blockchain with no on-chain features, such as e.g.
//    /// timelocks or hashlocks, needed to complete the swap.
//    Accordant,
//}

/// An arbitrating is the blockchain which will act as the decision engine, the arbitrating
/// blockchain will use transaction to transfer the funds on both blockchains.
pub trait Arbitrating:
    Asset + Keys + Commitment + Signatures + Onchain + Fee + FromSeed<Arb> + Clone + Eq
{
    /// Defines the address format for the arbitrating blockchain
    type Address: Clone + Debug + StrictEncode + StrictDecode;

    /// Defines the type of timelock used for the arbitrating transactions
    type Timelock: Copy + Debug + Encodable + Decodable + PartialEq + Eq;

    ///// Returns the blockchain role
    //fn role(&self) -> BlockchainRole {
    //    BlockchainRole::Arbitrating
    //}
}

/// An accordant is the blockchain which does not need transaction inside the protocol nor
/// timelocks, it is the blockchain with the less requirements for an atomic swap.
pub trait Accordant:
    Asset + Keys + Commitment + SharedPrivateKeys<Acc> + FromSeed<Acc> + Clone + Eq
{
    ///// Returns the blockchain role
    //fn role(&self) -> BlockchainRole {
    //    BlockchainRole::Accordant
    //}
}

/// Defines the role of a blockchain. Farcaster uses two blockchain roles (1) [Arbitrating] and (2)
/// [Accordant].
pub trait Blockchain {
    /// The list of keys available for a blockchain role.
    type KeyList;
}

/// Concrete type for the arbitrating blockchain role used when a trait implementation is needed
/// per blockchain role, such as [FromSeed].
pub struct Arb;

impl Blockchain for Arb {
    type KeyList = ArbitratingKey;
}

/// Concrete type for the accordant blockchain role used when a trait implementation is needed per
/// blockchain role, such as [FromSeed].
pub struct Acc;

impl Blockchain for Acc {
    type KeyList = AccordantKey;
}
