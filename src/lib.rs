//! Farcaster Core library

pub mod blockchains;
pub mod messages;
pub mod negotiation;
pub mod roles;
pub mod session;
pub mod instructions;
pub mod version;

#[cfg(test)]
mod tests {
    use bitcoin::util::amount::Amount;
    use super::blockchains::{Bitcoin, Blockchain, Monero};
    use super::negotiation::Offer;

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
