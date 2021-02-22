//! Farcaster Core library

pub mod blockchain;
pub mod messages;
pub mod negotiation;
pub mod roles;
pub mod session;

#[cfg(test)]
mod tests {
    use super::blockchain::{Bitcoin, Blockchain, Monero};
    use super::negotiation::Offer;

    #[test]
    fn create_offer() {
        let _ = Offer {
            arbitrating: Bitcoin::new(),
            accordant: Monero::new(),
            arbitrating_assets: 1,
            accordant_assets: 200,
            cancel_timelock: 10,
            punish_timelock: 10,
        };
    }
}
