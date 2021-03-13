//! Negotiation phase utilities

//use internet2::session::node_addr::NodeAddr;

use crate::blockchain::{Fee, FeeStrategy};
use crate::role::{Accordant, Arbitrating, Network, SwapRole};

/// An offer is created by a Maker before the start of his daemon, it references all the data
/// needed to know what the trade look likes from a Taker perspective. The daemon start when the
/// Maker is ready to finalyze his offer, transforming the offer into a public offer which contains
/// the data needed to a Taker to connect to the Maker's daemon.
pub struct Offer<Ar, Ac, S, N>
where
    Ar: Arbitrating + Fee,
    Ac: Accordant,
    S: FeeStrategy,
    N: Network,
{
    /// Type of offer and network to use
    pub network: N,
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
    pub fee_strategy: S,
    /// The future maker swap role
    pub maker_role: SwapRole,
}

/// Helper to create an offer from an arbitrating asset buyer perspective.
///
/// **This helper works only for buying Arbitrating assets with some Accordant assets**. The
/// reverse is not implemented for the `Buy` helper. You should use the `Sell` helper.
pub struct Buy<T, U, S, N>(BuilderState<T, U, S, N>)
where
    T: Arbitrating + Fee,
    U: Accordant,
    S: FeeStrategy,
    N: Network;

impl<T, U, S, N> Buy<T, U, S, N>
where
    T: Arbitrating + Fee,
    U: Accordant,
    S: FeeStrategy,
    N: Network,
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
    pub fn with(&mut self, asset: U, amount: U::AssetUnit) -> &Self {
        self.0.accordant = Some(asset);
        self.0.accordant_assets = Some(amount);
        self
    }

    /// Sets the timelocks for the proposed offer
    pub fn with_timelocks(&mut self, cancel: T::Timelock, punish: T::Timelock) -> &Self {
        self.0.cancel_timelock = Some(cancel);
        self.0.punish_timelock = Some(punish);
        self
    }

    /// Sets the fee strategy for the proposed offer
    pub fn with_fee(&mut self, strategy: S) -> &Self {
        self.0.fee_strategy = Some(strategy);
        self
    }

    /// Sets the network for the proposed offer
    pub fn on(&mut self, network: N) -> &Self {
        self.0.network = Some(network);
        self
    }

    /// Transform the internal state into an offer if all parameters have been set properly,
    /// otherwise return `None`.
    ///
    /// This function automatically sets the maker swap role as **Alice** to comply with the buy
    /// contract.
    pub fn to_offer(&mut self) -> Option<Offer<T, U, S, N>> {
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
pub struct Sell<T, U, S, N>(BuilderState<T, U, S, N>)
where
    T: Arbitrating + Fee,
    U: Accordant,
    S: FeeStrategy,
    N: Network;

impl<T, U, S, N> Sell<T, U, S, N>
where
    T: Arbitrating + Fee,
    U: Accordant,
    S: FeeStrategy,
    N: Network,
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
    pub fn for_some(&mut self, asset: U, amount: U::AssetUnit) -> &Self {
        self.0.accordant = Some(asset);
        self.0.accordant_assets = Some(amount);
        self
    }

    /// Sets the timelocks for the proposed offer
    pub fn with_timelocks(&mut self, cancel: T::Timelock, punish: T::Timelock) -> &Self {
        self.0.cancel_timelock = Some(cancel);
        self.0.punish_timelock = Some(punish);
        self
    }

    /// Sets the fee strategy for the proposed offer
    pub fn with_fee(&mut self, strategy: S) -> &Self {
        self.0.fee_strategy = Some(strategy);
        self
    }

    /// Sets the network for the proposed offer
    pub fn on(&mut self, network: N) -> &Self {
        self.0.network = Some(network);
        self
    }

    /// Transform the internal state into an offer if all parameters have been set properly,
    /// otherwise return `None`.
    ///
    /// This function automatically sets the maker swap role as **Bob** to comply with the buy
    /// contract.
    pub fn to_offer(&mut self) -> Option<Offer<T, U, S, N>> {
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
struct BuilderState<Ar, Ac, S, N>
where
    Ar: Arbitrating + Fee,
    Ac: Accordant,
    S: FeeStrategy,
    N: Network,
{
    network: Option<N>,
    arbitrating: Option<Ar>,
    accordant: Option<Ac>,
    arbitrating_assets: Option<Ar::AssetUnit>,
    accordant_assets: Option<Ac::AssetUnit>,
    cancel_timelock: Option<Ar::Timelock>,
    punish_timelock: Option<Ar::Timelock>,
    fee_strategy: Option<S>,
    maker_role: Option<SwapRole>,
}

impl<Ar, Ac, S, N> Default for BuilderState<Ar, Ac, S, N>
where
    Ar: Arbitrating + Fee,
    Ac: Accordant,
    S: FeeStrategy,
    N: Network,
{
    fn default() -> BuilderState<Ar, Ac, S, N> {
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
pub struct PublicOffer<Ar, Ac, S, N>
where
    Ar: Arbitrating + Fee,
    Ac: Accordant,
    S: FeeStrategy,
    N: Network,
{
    pub offer: Offer<Ar, Ac, S, N>,
    //pub daemon_service: NodeAddr,
}

#[cfg(test)]
mod tests {
    use super::{Buy, Offer, Sell};
    use crate::blockchain::{
        bitcoin::Bitcoin, bitcoin::SatPerVByte, monero::Monero, Blockchain, FixeFee,
    };
    use crate::role::{Local, SwapRole};
    use bitcoin::util::amount::Amount;

    #[test]
    fn create_offer() {
        let _ = Offer {
            network: Local,
            arbitrating: Bitcoin::new(),
            accordant: Monero::new(),
            arbitrating_assets: Amount::from_sat(1),
            accordant_assets: 200,
            cancel_timelock: 10,
            punish_timelock: 10,
            fee_strategy: FixeFee::<Bitcoin>::new(SatPerVByte::from_sat(20)),
            maker_role: SwapRole::Alice,
        };
    }

    #[test]
    fn maker_buy_arbitrating_assets_offer() {
        let mut buy = Buy::some(Bitcoin::new(), Amount::from_sat(100000));
        buy.with(Monero::new(), 200);
        buy.with_timelocks(10, 10);
        buy.with_fee(FixeFee::<Bitcoin>::new(SatPerVByte::from_sat(20)));
        buy.on(Local);
        assert!(buy.to_offer().is_some());
        assert_eq!(
            buy.to_offer().expect("an offer").maker_role,
            SwapRole::Alice
        );
    }

    #[test]
    fn maker_sell_arbitrating_assets_offer() {
        let mut sell = Sell::some(Bitcoin::new(), Amount::from_sat(100000));
        sell.for_some(Monero::new(), 200);
        sell.with_timelocks(10, 10);
        sell.with_fee(FixeFee::<Bitcoin>::new(SatPerVByte::from_sat(20)));
        sell.on(Local);
        assert!(sell.to_offer().is_some());
        assert_eq!(sell.to_offer().expect("an offer").maker_role, SwapRole::Bob);
    }
}
