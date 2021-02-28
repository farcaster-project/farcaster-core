//! Negotiation phase utilities

//use internet2::session::node_addr::NodeAddr;

use crate::blockchains::{Blockchain, Fee, FeeStrategy};
use crate::roles::{Accordant, Arbitrating, Network, SwapRole};

/// An offer is created by a Maker before the start of his daemon, it references all the data
/// needed to know what the trade look likes from a Taker perspective. The daemon start when the
/// Maker is ready to finalyze his offer, transforming the offer into a public offer which contains
/// the data needed to a Taker to connect to the Maker's daemon.
pub struct Offer<Ar, Ac, S, N>
where
    Ar: Arbitrating + Fee<S>,
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

// Buy some Ar with Ac -> role: Alice
// Buy some Ac with Ar -> role: Bob

pub trait Buyer<T, U, S, N>
where
    T: Blockchain,
    U: Blockchain,
    S: FeeStrategy,
    N: Network,
{
    type V: Arbitrating + Fee<S>;
    type W: Accordant;

    fn some(asset: T, amount: T::AssetUnit) -> Self;

    fn with(&mut self, asset: U, amount: U::AssetUnit) -> &Self;

    fn with_timelocks(
        &mut self,
        cancel: <Self::V as Arbitrating>::Timelock,
        punish: <Self::V as Arbitrating>::Timelock,
    ) -> &Self;

    fn with_fee(&mut self, strategy: S) -> &Self;

    fn on(&mut self, network: N) -> &Self;

    fn to_offer(&mut self) -> Option<Offer<Self::V, Self::W, S, N>>;
}

pub struct Buy<T, U, S, N>(Builder<T, U, S, N>)
where
    T: Arbitrating + Fee<S>,
    U: Accordant,
    S: FeeStrategy,
    N: Network;

impl<T, U, S, N> Buyer<T, U, S, N> for Buy<T, U, S, N>
where
    T: Arbitrating + Fee<S>,
    U: Accordant,
    S: FeeStrategy,
    N: Network,
{
    type V = T;
    type W = U;

    fn some(asset: T, amount: T::AssetUnit) -> Self {
        let mut buy = Self(Builder::default());
        buy.0.arbitrating = Some(asset);
        buy.0.arbitrating_assets = Some(amount);
        buy
    }

    fn with(&mut self, asset: U, amount: U::AssetUnit) -> &Self {
        self.0.accordant = Some(asset);
        self.0.accordant_assets = Some(amount);
        self
    }

    fn with_timelocks(
        &mut self,
        cancel: <Self::V as Arbitrating>::Timelock,
        punish: <Self::V as Arbitrating>::Timelock,
    ) -> &Self {
        self.0.cancel_timelock = Some(cancel);
        self.0.punish_timelock = Some(punish);
        self
    }

    fn with_fee(&mut self, strategy: S) -> &Self {
        self.0.fee_strategy = Some(strategy);
        self
    }

    fn on(&mut self, network: N) -> &Self {
        self.0.network = Some(network);
        self
    }

    fn to_offer(&mut self) -> Option<Offer<Self::V, Self::W, S, N>> {
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

struct Builder<Ar, Ac, S, N>
where
    Ar: Arbitrating + Fee<S>,
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

impl<Ar, Ac, S, N> Default for Builder<Ar, Ac, S, N>
where
    Ar: Arbitrating + Fee<S>,
    Ac: Accordant,
    S: FeeStrategy,
    N: Network,
{
    fn default() -> Builder<Ar, Ac, S, N> {
        Builder {
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

pub struct PublicOffer<Ar, Ac, S, N>
where
    Ar: Arbitrating + Fee<S>,
    Ac: Accordant,
    S: FeeStrategy,
    N: Network,
{
    pub offer: Offer<Ar, Ac, S, N>,
    //pub daemon_service: NodeAddr,
}

#[cfg(test)]
mod tests {
    use super::{Buy, Buyer, Offer};
    use crate::blockchains::{
        bitcoin::Bitcoin, bitcoin::SatPerVByte, monero::Monero, Blockchain, FixeFee,
    };
    use crate::roles::{Local, SwapRole};
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
            fee_strategy: FixeFee::new(SatPerVByte::from_sat(20)),
            maker_role: SwapRole::Alice,
        };
    }

    #[test]
    fn buy_arbitrating_assets_offer() {
        let mut buy = Buy::some(Bitcoin::new(), Amount::from_sat(100000));
        buy.with(Monero::new(), 200);
        buy.with_timelocks(10, 10);
        buy.with_fee(FixeFee::new(SatPerVByte::from_sat(20)));
        buy.on(Local);
        assert!(buy.to_offer().is_some());
        assert_eq!(
            buy.to_offer().expect("an offer").maker_role,
            SwapRole::Alice
        );
    }
}
