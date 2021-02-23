//! Negotiation Phase utilities

use crate::blockchains::Blockchain;
use crate::crypto::CryptoEngine;
use crate::roles::{Accordant, Arbitrating};

use crate::roles::SwapRole;

pub struct Offer<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    pub arbitrating: Ar,
    pub accordant: Ac,
    pub arbitrating_assets: Ar::AssetUnit,
    pub accordant_assets: Ac::AssetUnit,
    pub cancel_timelock: u64,
    pub punish_timelock: u64,
}

pub struct PublicOffer<Ar, Ac>
where
    Ar: Arbitrating,
    Ac: Accordant,
{
    pub offer: Offer<Ar, Ac>,
    pub maker_role: SwapRole,
    pub daemon_service: String,
}

#[cfg(test)]
mod tests {
    use super::Offer;
    use crate::blockchains::{Bitcoin, Blockchain, Monero};
    use bitcoin::util::amount::Amount;

    #[test]
    fn create_offer() {
        let _ = Offer::<Bitcoin, Monero> {
            arbitrating: Bitcoin::new(),
            accordant: Monero::new(),
            arbitrating_assets: Amount::from_sat(1),
            accordant_assets: 200,
            cancel_timelock: 10,
            punish_timelock: 10,
        };
    }
}
