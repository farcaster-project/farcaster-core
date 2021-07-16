use farcaster_core::chain::bitcoin::fee::SatPerVByte;
use farcaster_core::chain::bitcoin::timelock::CSVTimelock;
use farcaster_core::chain::bitcoin::Bitcoin;
use farcaster_core::chain::monero::Monero;
use farcaster_core::chain::pairs::btcxmr::BtcXmr;

use farcaster_core::blockchain::{FeeStrategy, Network};
use farcaster_core::consensus::{self, deserialize, serialize_hex};
use farcaster_core::negotiation::{Buy, Offer, PublicOffer, Sell};
use farcaster_core::role::SwapRole;

use bitcoin::Amount;

use internet2::{RemoteNodeAddr, RemoteSocketAddr};

use std::str::FromStr;

#[test]
fn create_offer() {
    let hex = "02000000808000008008000500000000000000080006000000000000000400070000000400080000000\
               10800090000000000000002";
    let offer: Offer<BtcXmr> = Offer {
        network: Network::Testnet,
        arbitrating_blockchain: Bitcoin,
        accordant_blockchain: Monero,
        arbitrating_amount: Amount::from_sat(5),
        accordant_amount: monero::Amount::from_pico(6),
        cancel_timelock: CSVTimelock::new(7),
        punish_timelock: CSVTimelock::new(8),
        fee_strategy: FeeStrategy::Fixed(SatPerVByte::from_sat(9)),
        maker_role: SwapRole::Bob,
    };

    assert_eq!(hex, serialize_hex(&offer));
    let strict_ser = strict_encoding::strict_serialize(&offer).unwrap();
    assert_eq!(&hex::decode(hex).unwrap(), &strict_ser);
    let res: Offer<BtcXmr> = strict_encoding::strict_deserialize(&strict_ser).unwrap();
    assert_eq!(&offer, &res);
}

#[test]
fn maker_buy_arbitrating_assets_offer() {
    let offer: Option<Offer<BtcXmr>> = Buy::some(Bitcoin, Amount::from_sat(100000))
        .with(Monero, monero::Amount::from_pico(200))
        .with_timelocks(CSVTimelock::new(10), CSVTimelock::new(10))
        .with_fee(FeeStrategy::Fixed(SatPerVByte::from_sat(20)))
        .on(Network::Testnet)
        .to_offer();
    assert!(offer.is_some());
    assert_eq!(offer.expect("an offer").maker_role, SwapRole::Alice);
}

#[test]
fn maker_sell_arbitrating_assets_offer() {
    let offer: Option<Offer<BtcXmr>> = Sell::some(Bitcoin, Amount::from_sat(100000))
        .for_some(Monero, monero::Amount::from_pico(200))
        .with_timelocks(CSVTimelock::new(10), CSVTimelock::new(10))
        .with_fee(FeeStrategy::Fixed(SatPerVByte::from_sat(20)))
        .on(Network::Testnet)
        .to_offer();
    assert!(offer.is_some());
    assert_eq!(offer.expect("an offer").maker_role, SwapRole::Bob);
}

#[test]
fn serialize_public_offer() {
    let hex = "46435357415001000200000080800000800800a0860100000000000800c80000000000000004000\
               a00000004000a00000001080014000000000000000203b31a0a70343bb46f3db3768296ac5027f9\
               873921b37f852860c690063ff9e4c90000000000000000000000000000000000000000000000000\
               000000000000000000000260700";
    let offer: Offer<BtcXmr> = Sell::some(Bitcoin, Amount::from_sat(100000))
        .for_some(Monero, monero::Amount::from_pico(200))
        .with_timelocks(CSVTimelock::new(10), CSVTimelock::new(10))
        .with_fee(FeeStrategy::Fixed(SatPerVByte::from_sat(20)))
        .on(Network::Testnet)
        .to_offer()
        .unwrap();
    let overlay = FromStr::from_str("tcp").unwrap();
    let ip = FromStr::from_str("0.0.0.0").unwrap();
    let port = FromStr::from_str("9735").unwrap();
    let remote_addr = RemoteSocketAddr::with_ip_addr(overlay, ip, port);

    let secp = secp256k1::Secp256k1::new();
    let sk = bitcoin::PrivateKey::from_wif("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D")
        .unwrap()
        .key;
    let node_id = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let peer = RemoteNodeAddr {
        node_id,
        remote_addr,
    };
    let public_offer = offer.to_public_v1(peer);

    assert_eq!(hex, serialize_hex(&public_offer));
    let strict_ser = strict_encoding::strict_serialize(&public_offer).unwrap();
    assert_eq!(&hex::decode(hex).unwrap(), &strict_ser);
    let res: PublicOffer<BtcXmr> = strict_encoding::strict_deserialize(&strict_ser).unwrap();
    assert_eq!(&public_offer, &res);
}

#[test]
fn check_public_offer_magic_bytes() {
    let valid = "46435357415001000200000080800000800800a0860100000000000800c80000000000000004000\
                 a00000004000a00000001080014000000000000000203b31a0a70343bb46f3db3768296ac5027f9\
                 873921b37f852860c690063ff9e4c90000000000000000000000000000000000000000000000000\
                 000000000000000000000260700";
    let pub_offer: Result<PublicOffer<BtcXmr>, consensus::Error> =
        deserialize(&hex::decode(valid).unwrap()[..]);
    assert!(pub_offer.is_ok());

    let invalid = "474353574150010002000000808000008008a08601000000000008c800000000000000040a00000\
                   0040a0000000108140000000000000002";
    let pub_offer: Result<PublicOffer<BtcXmr>, consensus::Error> =
        deserialize(&hex::decode(invalid).unwrap()[..]);
    assert!(pub_offer.is_err());
}
