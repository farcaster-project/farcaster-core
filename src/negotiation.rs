//! Negotiation phase utilities

//use internet2::session::node_addr::NodeAddr;

use crate::blockchains::{Fee, FeeStrategy};
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
    use super::Offer;
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
}