//! Negotiation phase utilities

//use internet2::session::node_addr::NodeAddr;

use std::io;

use crate::blockchain::{FeeStrategy, Network};
use crate::consensus::{self, Decodable, Encodable};
use crate::role::{Accordant, Arbitrating, SwapRole};

/// First six magic bytes of a public offer
pub const OFFER_MAGIC_BYTES: &[u8] = b"FCSWAP";

/// A public offer version containing the version and the activated features if any.
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

/// Negotiation errors used when manipulating offers, public offers and its version.
pub enum Error {
    /// The magic bytes of the offer does not match
    IncorrectMagicBytes,
}

/// An offer is created by a Maker before the start of his daemon, it references all the data
/// needed to know what the trade look likes from a Taker perspective. The daemon start when the
/// Maker is ready to finalyze his offer, transforming the offer into a public offer which contains
/// the data needed to a Taker to connect to the Maker's daemon.
pub struct Offer<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    /// Type of offer and network to use
    pub network: Network,
    /// The chosen arbitrating blockchain
    pub arbitrating: Ar,
    /// The chosen accordant blockchain
    pub accordant: Ac,
    /// Amount of arbitrating assets to exchanged
    pub arbitrating_assets: Ar::AssetUnit,
    /// Amount of accordant assets to exchanged
    pub accordant_assets: Ac::AssetUnit,
    /// The cancel timelock parameter of the arbitrating blockchain
    pub cancel_timelock: Ar::Timelock,
    /// The punish timelock parameter of the arbitrating blockchain
    pub punish_timelock: Ar::Timelock,
    /// The chosen fee strategy for the arbitrating transactions
    pub fee_strategy: FeeStrategy<Ar::FeeUnit>,
    /// The future maker swap role
    pub maker_role: SwapRole,
}

/// Helper to create an offer from an arbitrating asset buyer perspective.
///
/// **This helper works only for buying Arbitrating assets with some Accordant assets**. The
/// reverse is not implemented for the `Buy` helper. You should use the `Sell` helper.
pub struct Buy<T, U>(BuilderState<T, U>)
where
    T: Arbitrating,
    U: Accordant;

impl<T, U> Buy<T, U>
where
    T: Arbitrating,
    U: Accordant,
{
    /// Defines the asset and its amount the maker will receive in exchange of the asset and amount
    /// defined in the `with` method.
    pub fn some(asset: T, amount: T::AssetUnit) -> Self {
        let mut buy = Self(BuilderState::default());
        buy.0.arbitrating = Some(asset);
        buy.0.arbitrating_assets = Some(amount);
        buy
    }

    /// Defines the asset and its amount the maker will send to get the assets defined in the
    /// `some` method.
    pub fn with(mut self, asset: U, amount: U::AssetUnit) -> Self {
        self.0.accordant = Some(asset);
        self.0.accordant_assets = Some(amount);
        self
    }

    /// Sets the timelocks for the proposed offer
    pub fn with_timelocks(mut self, cancel: T::Timelock, punish: T::Timelock) -> Self {
        self.0.cancel_timelock = Some(cancel);
        self.0.punish_timelock = Some(punish);
        self
    }

    /// Sets the fee strategy for the proposed offer
    pub fn with_fee(mut self, strategy: FeeStrategy<T::FeeUnit>) -> Self {
        self.0.fee_strategy = Some(strategy);
        self
    }

    /// Sets the network for the proposed offer
    pub fn on(mut self, network: Network) -> Self {
        self.0.network = Some(network);
        self
    }

    /// Transform the internal state into an offer if all parameters have been set properly,
    /// otherwise return `None`.
    ///
    /// This function automatically sets the maker swap role as **Alice** to comply with the buy
    /// contract.
    pub fn to_offer(mut self) -> Option<Offer<T, U>> {
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
/// **This helper works only for selling Arbitrating assets for some Accordant assets**. The
/// reverse is not implemented for the `Sell` helper. You should use the `Buy` helper.
pub struct Sell<T, U>(BuilderState<T, U>)
where
    T: Arbitrating,
    U: Accordant;

impl<T, U> Sell<T, U>
where
    T: Arbitrating,
    U: Accordant,
{
    /// Defines the asset and its amount the maker will send to get the assets defined in the
    /// `for_some` method.
    pub fn some(asset: T, amount: T::AssetUnit) -> Self {
        let mut buy = Self(BuilderState::default());
        buy.0.arbitrating = Some(asset);
        buy.0.arbitrating_assets = Some(amount);
        buy
    }

    /// Defines the asset and its amount the maker will receive in exchange of the asset and amount
    /// defined in the `some` method.
    pub fn for_some(mut self, asset: U, amount: U::AssetUnit) -> Self {
        self.0.accordant = Some(asset);
        self.0.accordant_assets = Some(amount);
        self
    }

    /// Sets the timelocks for the proposed offer
    pub fn with_timelocks(mut self, cancel: T::Timelock, punish: T::Timelock) -> Self {
        self.0.cancel_timelock = Some(cancel);
        self.0.punish_timelock = Some(punish);
        self
    }

    /// Sets the fee strategy for the proposed offer
    pub fn with_fee(mut self, strategy: FeeStrategy<T::FeeUnit>) -> Self {
        self.0.fee_strategy = Some(strategy);
        self
    }

    /// Sets the network for the proposed offer
    pub fn on(mut self, network: Network) -> Self {
        self.0.network = Some(network);
        self
    }

    /// Transform the internal state into an offer if all parameters have been set properly,
    /// otherwise return `None`.
    ///
    /// This function automatically sets the maker swap role as **Bob** to comply with the buy
    /// contract.
    pub fn to_offer(mut self) -> Option<Offer<T, U>> {
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
struct BuilderState<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    network: Option<Network>,
    arbitrating: Option<Ar>,
    accordant: Option<Ac>,
    arbitrating_assets: Option<Ar::AssetUnit>,
    accordant_assets: Option<Ac::AssetUnit>,
    cancel_timelock: Option<Ar::Timelock>,
    punish_timelock: Option<Ar::Timelock>,
    fee_strategy: Option<FeeStrategy<Ar::FeeUnit>>,
    maker_role: Option<SwapRole>,
}

impl<Ar, Ac> Default for BuilderState<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    fn default() -> BuilderState<Ar, Ac> {
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

/// A public offer is shared across maker's prefered network to signal is willing of trading some
/// assets at some conditions. The assets and condition are defined in the offer, the make peer
/// connection information are happen to the offer the create a public offer.
pub struct PublicOffer<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    /// The public offer version
    pub version: Version,
    /// The content of the offer
    pub offer: Offer<Ar, Ac>,
    //pub daemon_service: NodeAddr,
}

#[cfg(test)]
mod tests {
    use super::{Buy, Offer, Sell};
    use crate::bitcoin::{Bitcoin, CSVTimelock, SatPerVByte};
    use crate::blockchain::{Blockchain, FeeStrategy, Network};
    use crate::monero::Monero;
    use crate::role::SwapRole;
    use bitcoin::util::amount::Amount;

    #[test]
    fn create_offer() {
        let _ = Offer {
            network: Network::Testnet,
            arbitrating: Bitcoin::new(),
            accordant: Monero::new(),
            arbitrating_assets: Amount::from_sat(1),
            accordant_assets: 200,
            cancel_timelock: CSVTimelock::new(10),
            punish_timelock: CSVTimelock::new(10),
            fee_strategy: FeeStrategy::Fixed(SatPerVByte::from_sat(20)),
            maker_role: SwapRole::Alice,
        };
    }

    #[test]
    fn maker_buy_arbitrating_assets_offer() {
        let offer = Buy::some(Bitcoin::new(), Amount::from_sat(100000))
            .with(Monero::new(), 200)
            .with_timelocks(CSVTimelock::new(10), CSVTimelock::new(10))
            .with_fee(FeeStrategy::Fixed(SatPerVByte::from_sat(20)))
            .on(Network::Testnet)
            .to_offer();
        assert!(offer.is_some());
        assert_eq!(offer.expect("an offer").maker_role, SwapRole::Alice);
    }

    #[test]
    fn maker_sell_arbitrating_assets_offer() {
        let offer = Sell::some(Bitcoin::new(), Amount::from_sat(100000))
            .for_some(Monero::new(), 200)
            .with_timelocks(CSVTimelock::new(10), CSVTimelock::new(10))
            .with_fee(FeeStrategy::Fixed(SatPerVByte::from_sat(20)))
            .on(Network::Testnet)
            .to_offer();
        assert!(offer.is_some());
        assert_eq!(offer.expect("an offer").maker_role, SwapRole::Bob);
    }
}
