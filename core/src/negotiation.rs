//! Negotiation phase utilities

use internet2::RemoteNodeAddr;
use strict_encoding::{StrictDecode, StrictEncode};
use thiserror::Error;

use std::io;

use crate::blockchain::{Asset, Fee, FeeStrategy, Network, Timelock};
use crate::consensus::{self, Decodable, Encodable};
use crate::role::{NegotiationRole, SwapRole};
use crate::swap::Swap;

/// First six magic bytes of a public offer
pub const OFFER_MAGIC_BYTES: &[u8; 6] = b"FCSWAP";

/// A public offer version containing the version and the activated features if
/// any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version(u16);

impl Version {
    /// Create a new version 1 public offer
    pub fn new_v1() -> Self {
        Self::new(1)
    }

    /// Create a public offer from a raw version and feature `u16`
    pub fn new(version: u16) -> Self {
        Version(version)
    }

    /// Version and features as `u16`
    pub fn to_u16(&self) -> u16 {
        self.0
    }
}

impl Encodable for Version {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        self.to_u16().consensus_encode(writer)
    }
}

impl Decodable for Version {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self::new(Decodable::consensus_decode(d)?))
    }
}

/// Negotiation errors used when manipulating offers, public offers and its
/// version.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum Error {
    /// The magic bytes of the offer does not match
    #[error("Incorrect magic bytes")]
    IncorrectMagicBytes,
}

/// An offer is created by a Maker before the start of his daemon, it references all the data
/// needed to know what the trade look likes from a Taker perspective. The daemon start when the
/// Maker is ready to finalyze his offer, transforming the offer into a public offer which contains
/// the data needed to a Taker to connect to the Maker's daemon.
#[derive(Debug, Clone)]
pub struct Offer<Ctx: Swap> {
    /// Type of offer and network to use
    pub network: Network,
    /// The chosen arbitrating blockchain
    pub arbitrating: Ctx::Ar,
    /// The chosen accordant blockchain
    pub accordant: Ctx::Ac,
    /// Amount of arbitrating assets to exchanged
    pub arbitrating_assets: <Ctx::Ar as Asset>::AssetUnit,
    /// Amount of accordant assets to exchanged
    pub accordant_assets: <Ctx::Ac as Asset>::AssetUnit,
    /// The cancel timelock parameter of the arbitrating blockchain
    pub cancel_timelock: <Ctx::Ar as Timelock>::Timelock,
    /// The punish timelock parameter of the arbitrating blockchain
    pub punish_timelock: <Ctx::Ar as Timelock>::Timelock,
    /// The chosen fee strategy for the arbitrating transactions
    pub fee_strategy: FeeStrategy<<Ctx::Ar as Fee>::FeeUnit>,
    /// The future maker swap role
    pub maker_role: SwapRole,
}

impl<Ctx: Swap> Eq for Offer<Ctx> {}

impl<Ctx: Swap> PartialEq for Offer<Ctx> {
    fn eq(&self, other: &Self) -> bool {
        consensus::serialize_hex(self) == consensus::serialize_hex(other)
    }
}

impl<Ctx: Swap> Offer<Ctx> {
    /// Transform the offer in a public offer of [Version] 1
    pub fn to_public_v1(self, daemon_service: RemoteNodeAddr) -> PublicOffer<Ctx> {
        PublicOffer {
            version: Version::new_v1(),
            offer: self,
            daemon_service,
        }
    }

    /// Return the future swap role for the given negotiation role.
    pub fn swap_role(&self, nego_role: &NegotiationRole) -> SwapRole {
        match nego_role {
            NegotiationRole::Maker => self.maker_role,
            NegotiationRole::Taker => self.maker_role.other(),
        }
    }
}

impl<Ctx> Encodable for Offer<Ctx>
where
    Ctx: Swap,
{
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = self.network.consensus_encode(writer)?;
        len += self.arbitrating.consensus_encode(writer)?;
        len += self.accordant.consensus_encode(writer)?;
        len += wrap_in_vec!(wrap arbitrating_assets for self in writer);
        len += wrap_in_vec!(wrap accordant_assets for self in writer);
        len += wrap_in_vec!(wrap cancel_timelock for self in writer);
        len += wrap_in_vec!(wrap punish_timelock for self in writer);
        len += self.fee_strategy.consensus_encode(writer)?;
        Ok(len + self.maker_role.consensus_encode(writer)?)
    }
}

impl<Ctx> Decodable for Offer<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Offer {
            network: Decodable::consensus_decode(d)?,
            arbitrating: Decodable::consensus_decode(d)?,
            accordant: Decodable::consensus_decode(d)?,
            arbitrating_assets: unwrap_from_vec!(d),
            accordant_assets: unwrap_from_vec!(d),
            cancel_timelock: unwrap_from_vec!(d),
            punish_timelock: unwrap_from_vec!(d),
            fee_strategy: Decodable::consensus_decode(d)?,
            maker_role: Decodable::consensus_decode(d)?,
        })
    }
}

/// Helper to create an offer from an arbitrating asset buyer perspective.
///
/// **This helper works only for buying Arbitrating assets with some Accordant
/// assets**. The reverse is not implemented for the [Buy] helper. You should
/// use the [Sell] helper.
pub struct Buy<Ctx>(BuilderState<Ctx>)
where
    Ctx: Swap;

impl<Ctx> Buy<Ctx>
where
    Ctx: Swap,
{
    /// Defines the asset and its amount the maker will receive in exchange of
    /// the asset and amount defined in the `with` method.
    pub fn some(asset: Ctx::Ar, amount: <Ctx::Ar as Asset>::AssetUnit) -> Self {
        let mut buy = Self(BuilderState::default());
        buy.0.arbitrating = Some(asset);
        buy.0.arbitrating_assets = Some(amount);
        buy
    }

    /// Defines the asset and its amount the maker will send to get the assets
    /// defined in the `some` method.
    pub fn with(mut self, asset: Ctx::Ac, amount: <Ctx::Ac as Asset>::AssetUnit) -> Self {
        self.0.accordant = Some(asset);
        self.0.accordant_assets = Some(amount);
        self
    }

    /// Sets the timelocks for the proposed offer
    pub fn with_timelocks(
        mut self,
        cancel: <Ctx::Ar as Timelock>::Timelock,
        punish: <Ctx::Ar as Timelock>::Timelock,
    ) -> Self {
        self.0.cancel_timelock = Some(cancel);
        self.0.punish_timelock = Some(punish);
        self
    }

    /// Sets the fee strategy for the proposed offer
    pub fn with_fee(mut self, strategy: FeeStrategy<<Ctx::Ar as Fee>::FeeUnit>) -> Self {
        self.0.fee_strategy = Some(strategy);
        self
    }

    /// Sets the network for the proposed offer
    pub fn on(mut self, network: Network) -> Self {
        self.0.network = Some(network);
        self
    }

    /// Transform the internal state into an offer if all parameters have been
    /// set properly, otherwise return `None`.
    ///
    /// This function automatically sets the maker swap role as **Alice** to
    /// comply with the buy contract.
    pub fn to_offer(mut self) -> Option<Offer<Ctx>> {
        self.0.maker_role = Some(SwapRole::Alice);
        Some(Offer {
            network: self.0.network?,
            arbitrating: self.0.arbitrating?,
            accordant: self.0.accordant?,
            arbitrating_assets: self.0.arbitrating_assets?,
            accordant_assets: self.0.accordant_assets?,
            cancel_timelock: self.0.cancel_timelock?,
            punish_timelock: self.0.punish_timelock?,
            fee_strategy: self.0.fee_strategy?,
            maker_role: self.0.maker_role?,
        })
    }
}

/// Helper to create an offer from an arbitrating asset seller perspective.
///
/// **This helper works only for selling Arbitrating assets for some Accordant
/// assets**. The reverse is not implemented for the [Sell] helper. You should
/// use the [Buy] helper.
pub struct Sell<Ctx>(BuilderState<Ctx>)
where
    Ctx: Swap;

impl<Ctx> Sell<Ctx>
where
    Ctx: Swap,
{
    /// Defines the asset and its amount the maker will send to get the assets
    /// defined in the `for_some` method.
    pub fn some(asset: Ctx::Ar, amount: <Ctx::Ar as Asset>::AssetUnit) -> Self {
        let mut buy = Self(BuilderState::default());
        buy.0.arbitrating = Some(asset);
        buy.0.arbitrating_assets = Some(amount);
        buy
    }

    /// Defines the asset and its amount the maker will receive in exchange of
    /// the asset and amount defined in the `some` method.
    pub fn for_some(mut self, asset: Ctx::Ac, amount: <Ctx::Ac as Asset>::AssetUnit) -> Self {
        self.0.accordant = Some(asset);
        self.0.accordant_assets = Some(amount);
        self
    }

    /// Sets the timelocks for the proposed offer
    pub fn with_timelocks(
        mut self,
        cancel: <Ctx::Ar as Timelock>::Timelock,
        punish: <Ctx::Ar as Timelock>::Timelock,
    ) -> Self {
        self.0.cancel_timelock = Some(cancel);
        self.0.punish_timelock = Some(punish);
        self
    }

    /// Sets the fee strategy for the proposed offer
    pub fn with_fee(mut self, strategy: FeeStrategy<<Ctx::Ar as Fee>::FeeUnit>) -> Self {
        self.0.fee_strategy = Some(strategy);
        self
    }

    /// Sets the network for the proposed offer
    pub fn on(mut self, network: Network) -> Self {
        self.0.network = Some(network);
        self
    }

    /// Transform the internal state into an offer if all parameters have been
    /// set properly, otherwise return `None`.
    ///
    /// This function automatically sets the maker swap role as **Bob** to
    /// comply with the buy contract.
    pub fn to_offer(mut self) -> Option<Offer<Ctx>> {
        self.0.maker_role = Some(SwapRole::Bob);
        Some(Offer {
            network: self.0.network?,
            arbitrating: self.0.arbitrating?,
            accordant: self.0.accordant?,
            arbitrating_assets: self.0.arbitrating_assets?,
            accordant_assets: self.0.accordant_assets?,
            cancel_timelock: self.0.cancel_timelock?,
            punish_timelock: self.0.punish_timelock?,
            fee_strategy: self.0.fee_strategy?,
            maker_role: self.0.maker_role?,
        })
    }
}

// Internal state of an offer builder
struct BuilderState<Ctx: Swap> {
    network: Option<Network>,
    arbitrating: Option<Ctx::Ar>,
    accordant: Option<Ctx::Ac>,
    arbitrating_assets: Option<<Ctx::Ar as Asset>::AssetUnit>,
    accordant_assets: Option<<Ctx::Ac as Asset>::AssetUnit>,
    cancel_timelock: Option<<Ctx::Ar as Timelock>::Timelock>,
    punish_timelock: Option<<Ctx::Ar as Timelock>::Timelock>,
    fee_strategy: Option<FeeStrategy<<Ctx::Ar as Fee>::FeeUnit>>,
    maker_role: Option<SwapRole>,
}

impl<Ctx> Default for BuilderState<Ctx>
where
    Ctx: Swap,
{
    fn default() -> BuilderState<Ctx> {
        BuilderState {
            network: None,
            arbitrating: None,
            accordant: None,
            arbitrating_assets: None,
            accordant_assets: None,
            cancel_timelock: None,
            punish_timelock: None,
            fee_strategy: None,
            maker_role: None,
        }
    }
}

/// A public offer is shared across maker's prefered network to signal is
/// willing of trading some assets at some conditions. The assets and condition
/// are defined in the offer, the make peer connection information are happen to
/// the offer the create a public offer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicOffer<Ctx: Swap> {
    /// The public offer version
    pub version: Version,
    /// The content of the offer
    pub offer: Offer<Ctx>,
    /// Address of the listening daemon's peer
    pub daemon_service: RemoteNodeAddr,
}

impl<Ctx: Swap> PublicOffer<Ctx> {
    /// Return the future swap role for the given negotiation role.
    pub fn swap_role(&self, nego_role: &NegotiationRole) -> SwapRole {
        self.offer.swap_role(nego_role)
    }
}

impl<Ctx> std::fmt::Display for PublicOffer<Ctx>
where
    Ctx: Swap,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", consensus::serialize_hex(self))
    }
}

impl<Ctx> std::hash::Hash for PublicOffer<Ctx>
where
    Ctx: Swap,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let mut buf = io::Cursor::new(vec![]);
        self.consensus_encode(&mut buf).unwrap();
        buf.into_inner().hash(state)
    }
}

impl<Ctx> std::str::FromStr for PublicOffer<Ctx>
where
    Ctx: Swap,
{
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded =
            hex::decode(s).map_err(|_| consensus::Error::ParseFailed("Hex decode failed"))?;
        let mut res = std::io::Cursor::new(decoded);
        Decodable::consensus_decode(&mut res)
    }
}

impl<Ctx> Encodable for PublicOffer<Ctx>
where
    Ctx: Swap,
{
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = OFFER_MAGIC_BYTES.consensus_encode(writer)?;
        len += self.version.consensus_encode(writer)?;
        len += self.offer.consensus_encode(writer)?;
        len += strict_encoding::StrictEncode::strict_encode(&self.daemon_service, writer).map_err(
            |_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Failed to encode RemoteNodeAddr",
                )
            },
        )?;
        Ok(len)
    }
}

impl<Ctx> Decodable for PublicOffer<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let magic_bytes: [u8; 6] = Decodable::consensus_decode(d)?;
        if magic_bytes != *OFFER_MAGIC_BYTES {
            return Err(consensus::Error::Negotiation(Error::IncorrectMagicBytes));
        }
        Ok(PublicOffer {
            version: Decodable::consensus_decode(d)?,
            offer: Decodable::consensus_decode(d)?,
            daemon_service: strict_encoding::StrictDecode::strict_decode(d)
                .map_err(|_| consensus::Error::ParseFailed("Failed to decode RemoteNodeAddr"))?,
        })
    }
}

impl<Ctx> StrictEncode for PublicOffer<Ctx>
where
    Ctx: Swap,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        Encodable::consensus_encode(self, &mut e).map_err(strict_encoding::Error::from)
    }
}

impl<Ctx> StrictDecode for PublicOffer<Ctx>
where
    Ctx: Swap,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Decodable::consensus_decode(&mut d).map_err(|_| {
            strict_encoding::Error::DataIntegrityError(
                "Failed to decode the public offer".to_string(),
            )
        })
    }
}

impl<Ctx> StrictEncode for Offer<Ctx>
where
    Ctx: Swap,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, strict_encoding::Error> {
        Encodable::consensus_encode(self, &mut e).map_err(strict_encoding::Error::from)
    }
}

impl<Ctx> StrictDecode for Offer<Ctx>
where
    Ctx: Swap,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, strict_encoding::Error> {
        Decodable::consensus_decode(&mut d).map_err(|_| {
            strict_encoding::Error::DataIntegrityError("Failed to decode the offer".to_string())
        })
    }
}
