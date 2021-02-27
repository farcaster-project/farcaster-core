//! Negotiation Phase utilities

use crate::blockchains::{Fee, FeeStrategy};
use crate::roles::{Accordant, Arbitrating};
use inet2_addr::InetSocketAddrExt;

use crate::roles::SwapRole;

pub struct Offer<Ar, Ac, S>
where
    Ar: Arbitrating + Fee<S>,
    Ac: Accordant,
    S: FeeStrategy,
{
    pub arbitrating: Ar,
    pub accordant: Ac,
    pub arbitrating_assets: Ar::AssetUnit,
    pub accordant_assets: Ac::AssetUnit,
    pub cancel_timelock: u64,
    pub punish_timelock: u64,
    pub fee_strategy: S,
}

pub struct PublicOffer<Ar, Ac, S>
where
    Ar: Arbitrating + Fee<S>,
    Ac: Accordant,
    S: FeeStrategy,
{
    pub offer: Offer<Ar, Ac, S>,
    pub maker_role: SwapRole,
    pub daemon_service: InetSocketAddrExt,
}

#[cfg(test)]
mod tests {
    use super::Offer;
    use crate::blockchains::{
        bitcoin::Bitcoin, bitcoin::SatPerVByte, monero::Monero, Blockchain, FixeFee,
    };
    use bitcoin::util::amount::Amount;

    #[test]
    fn create_offer() {
        let _ = Offer::<Bitcoin, Monero, FixeFee<Bitcoin>> {
            arbitrating: Bitcoin::new(),
            accordant: Monero::new(),
            arbitrating_assets: Amount::from_sat(1),
            accordant_assets: 200,
            cancel_timelock: 10,
            punish_timelock: 10,
            fee_strategy: FixeFee::new(SatPerVByte::from_sat(20)),
        };
    }
}
