use farcaster_chains::bitcoin::{Amount, Bitcoin, CSVTimelock, SatPerVByte};
use farcaster_chains::monero::Monero;

use farcaster_core::blockchain::{Blockchain, FeeStrategy, Network};
use farcaster_core::consensus::{self, deserialize, serialize_hex};
use farcaster_core::negotiation::{Buy, Offer, PublicOffer, Sell};
use farcaster_core::role::SwapRole;

#[test]
fn create_offer() {
    let hex = "020000008080000080080500000000000000080600000000000000040700000004080000000108090000000000000002";
    let offer = Offer {
        network: Network::Testnet,
        arbitrating: Bitcoin::new(),
        accordant: Monero::new(),
        arbitrating_assets: Amount::from_sat(5),
        accordant_assets: 6,
        cancel_timelock: CSVTimelock::new(7),
        punish_timelock: CSVTimelock::new(8),
        fee_strategy: FeeStrategy::Fixed(SatPerVByte::from_sat(9)),
        maker_role: SwapRole::Bob,
    };

    assert_eq!(hex, serialize_hex(&offer));
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
    dbg!(&offer);
    assert_eq!(offer.expect("an offer").maker_role, SwapRole::Bob);
}

#[test]
fn serialize_public_offer() {
    let hex = "464353574150010002000000808000008008a08601000000000008c800000000000000040a000000040a0000000108140000000000000002";
    let offer = Sell::some(Bitcoin::new(), Amount::from_sat(100000))
        .for_some(Monero::new(), 200)
        .with_timelocks(CSVTimelock::new(10), CSVTimelock::new(10))
        .with_fee(FeeStrategy::Fixed(SatPerVByte::from_sat(20)))
        .on(Network::Testnet)
        .to_offer()
        .unwrap();
    let public_offer = offer.to_public_v1();

    assert_eq!(hex, serialize_hex(&public_offer));
}

#[test]
fn check_public_offer_magic_bytes() {
    let valid = "464353574150010002000000808000008008a08601000000000008c800000000000000040a000000040a0000000108140000000000000002";
    let pub_offer: Result<PublicOffer<Bitcoin, Monero>, consensus::Error> =
        deserialize(&hex::decode(valid).unwrap()[..]);
    dbg!(&pub_offer);
    assert!(pub_offer.is_ok());

    let invalid = "474353574150010002000000808000008008a08601000000000008c800000000000000040a000000040a0000000108140000000000000002";
    let pub_offer: Result<PublicOffer<Bitcoin, Monero>, consensus::Error> =
        deserialize(&hex::decode(invalid).unwrap()[..]);
    assert!(pub_offer.is_err());
}
