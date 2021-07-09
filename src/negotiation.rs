//! Negotiation phase utilities

use internet2::RemoteNodeAddr;
use thiserror::Error;

use std::io;

use crate::blockchain::{Asset, Fee, FeeStrategy, Network, Timelock};
use crate::consensus::{self, CanonicalBytes, Decodable, Encodable};
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
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        self.to_u16().consensus_encode(s)
    }
}

impl Decodable for Version {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self::new(Decodable::consensus_decode(d)?))
    }
}

/// Negotiation errors used when manipulating offers, public offers and its version.
#[derive(Error, Debug)]
pub enum Error {
    /// The public offer version is not supported.
    #[error("Unsupported version")]
    UnsupportedVersion,
    /// The public offer signature does not pass the validation tests.
    #[error("Invalid signature")]
    InvalidSignature,
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
    pub arbitrating_blockchain: Ctx::Ar,
    /// The chosen accordant blockchain
    pub accordant_blockchain: Ctx::Ac,
    /// Amount of arbitrating assets to exchanged
    pub arbitrating_amount: <Ctx::Ar as Asset>::AssetUnit,
    /// Amount of accordant assets to exchanged
    pub accordant_amount: <Ctx::Ac as Asset>::AssetUnit,
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
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.network.consensus_encode(s)?;
        len += self.arbitrating_blockchain.to_u32().consensus_encode(s)?;
        len += self.accordant_blockchain.to_u32().consensus_encode(s)?;
        len += self
            .arbitrating_amount
            .as_canonical_bytes()
            .consensus_encode(s)?;
        len += self
            .accordant_amount
            .as_canonical_bytes()
            .consensus_encode(s)?;
        len += self
            .cancel_timelock
            .as_canonical_bytes()
            .consensus_encode(s)?;
        len += self
            .punish_timelock
            .as_canonical_bytes()
            .consensus_encode(s)?;
        len += self.fee_strategy.consensus_encode(s)?;
        Ok(len + self.maker_role.consensus_encode(s)?)
    }
}

impl<Ctx> Decodable for Offer<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Offer {
            network: Decodable::consensus_decode(d)?,
            arbitrating_blockchain: Ctx::Ar::from_u32(Decodable::consensus_decode(d)?)
                .ok_or(consensus::Error::UnknownType)?,
            accordant_blockchain: Ctx::Ac::from_u32(Decodable::consensus_decode(d)?)
                .ok_or(consensus::Error::UnknownType)?,
            arbitrating_amount: <Ctx::Ar as Asset>::AssetUnit::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            accordant_amount: <Ctx::Ac as Asset>::AssetUnit::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            cancel_timelock: <Ctx::Ar as Timelock>::Timelock::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            punish_timelock: <Ctx::Ar as Timelock>::Timelock::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            fee_strategy: Decodable::consensus_decode(d)?,
            maker_role: Decodable::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(Offer<Ctx>, Ctx: Swap);

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
        buy.0.arbitrating_blockchain = Some(asset);
        buy.0.arbitrating_amount = Some(amount);
        buy
    }

    /// Defines the asset and its amount the maker will send to get the assets
    /// defined in the `some` method.
    pub fn with(mut self, asset: Ctx::Ac, amount: <Ctx::Ac as Asset>::AssetUnit) -> Self {
        self.0.accordant_blockchain = Some(asset);
        self.0.accordant_amount = Some(amount);
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
            arbitrating_blockchain: self.0.arbitrating_blockchain?,
            accordant_blockchain: self.0.accordant_blockchain?,
            arbitrating_amount: self.0.arbitrating_amount?,
            accordant_amount: self.0.accordant_amount?,
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
        buy.0.arbitrating_blockchain = Some(asset);
        buy.0.arbitrating_amount = Some(amount);
        buy
    }

    /// Defines the asset and its amount the maker will receive in exchange of
    /// the asset and amount defined in the `some` method.
    pub fn for_some(mut self, asset: Ctx::Ac, amount: <Ctx::Ac as Asset>::AssetUnit) -> Self {
        self.0.accordant_blockchain = Some(asset);
        self.0.accordant_amount = Some(amount);
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
            arbitrating_blockchain: self.0.arbitrating_blockchain?,
            accordant_blockchain: self.0.accordant_blockchain?,
            arbitrating_amount: self.0.arbitrating_amount?,
            accordant_amount: self.0.accordant_amount?,
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
    arbitrating_blockchain: Option<Ctx::Ar>,
    accordant_blockchain: Option<Ctx::Ac>,
    arbitrating_amount: Option<<Ctx::Ar as Asset>::AssetUnit>,
    accordant_amount: Option<<Ctx::Ac as Asset>::AssetUnit>,
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
            arbitrating_blockchain: None,
            accordant_blockchain: None,
            arbitrating_amount: None,
            accordant_amount: None,
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
        let decoded = hex::decode(s).map_err(consensus::Error::new)?;
        let mut res = std::io::Cursor::new(decoded);
        Decodable::consensus_decode(&mut res)
    }
}

impl<Ctx> Encodable for PublicOffer<Ctx>
where
    Ctx: Swap,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = OFFER_MAGIC_BYTES.consensus_encode(s)?;
        len += self.version.consensus_encode(s)?;
        len += self.offer.consensus_encode(s)?;
        len += strict_encoding::StrictEncode::strict_encode(&self.daemon_service, s).map_err(
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
            return Err(consensus::Error::IncorrectMagicBytes);
        }
        Ok(PublicOffer {
            version: Decodable::consensus_decode(d)?,
            offer: Decodable::consensus_decode(d)?,
            daemon_service: strict_encoding::StrictDecode::strict_decode(d)
                .map_err(consensus::Error::new)?,
        })
    }
}

impl_strict_encoding!(PublicOffer<Ctx>, Ctx: Swap);
