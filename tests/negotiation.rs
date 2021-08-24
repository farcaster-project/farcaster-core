use farcaster_core::bitcoin::fee::SatPerVByte;
use farcaster_core::bitcoin::timelock::CSVTimelock;
use farcaster_core::bitcoin::BitcoinSegwitV0;
use farcaster_core::monero::Monero;
use farcaster_core::swap::btcxmr::BtcXmr;

use farcaster_core::blockchain::{FeeStrategy, Network};
use farcaster_core::consensus::{self, deserialize, serialize_hex};
use farcaster_core::negotiation::{Buy, Offer, OfferId, PublicOffer, PublicOfferId, Sell};
use farcaster_core::role::SwapRole;

use bitcoin::Amount;

use inet2_addr::InetSocketAddr;

use std::str::FromStr;

#[test]
fn create_offer() {
    let hex = "02000000808000008008000500000000000000080006000000000000000400070000000400080000000\
               10800090000000000000002";
    let offer: Offer<BtcXmr> = Offer {
        network: Network::Testnet,
        arbitrating_blockchain: BitcoinSegwitV0::new(),
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
fn get_offer_id() {
    let hex = "02000000808000008008000500000000000000080006000000000000000400070000000400080000000\
               10800090000000000000002";
    let res: Offer<BtcXmr> =
        strict_encoding::strict_deserialize(&hex::decode(hex).unwrap()).unwrap();
    let id = OfferId::from_str("f79b29ccb233b37cea3aa35b94c5ece25c58a8098afc18f046810a3c04591599")
        .unwrap();
    assert_eq!(id, res.id());
}

#[test]
fn maker_buy_arbitrating_assets_offer() {
    let offer: Option<Offer<BtcXmr>> = Buy::some(BitcoinSegwitV0::new(), Amount::from_sat(100000))
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
    let offer: Option<Offer<BtcXmr>> = Sell::some(BitcoinSegwitV0::new(), Amount::from_sat(100000))
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
               a00000004000a000000010800140000000000000002210003b31a0a70343bb46f3db3768296ac50\
               27f9873921b37f852860c690063ff9e4c9000000000000000000000000000000000000000000000\
               00000000000000000000000260700";
    let offer: Offer<BtcXmr> = Sell::some(BitcoinSegwitV0::new(), Amount::from_sat(100000))
        .for_some(Monero, monero::Amount::from_pico(200))
        .with_timelocks(CSVTimelock::new(10), CSVTimelock::new(10))
        .with_fee(FeeStrategy::Fixed(SatPerVByte::from_sat(20)))
        .on(Network::Testnet)
        .to_offer()
        .unwrap();
    let ip = FromStr::from_str("0.0.0.0").unwrap();
    let port = FromStr::from_str("9735").unwrap();

    let secp = secp256k1::Secp256k1::new();
    let sk = bitcoin::PrivateKey::from_wif("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D")
        .unwrap()
        .key;
    let node_id = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let peer_address = InetSocketAddr::new(ip, port);
    let public_offer = offer.to_public_v1(node_id, peer_address);

    assert_eq!(hex, serialize_hex(&public_offer));
    let strict_ser = strict_encoding::strict_serialize(&public_offer).unwrap();
    assert_eq!(&hex::decode(hex).unwrap(), &strict_ser);
    let res: PublicOffer<BtcXmr> = strict_encoding::strict_deserialize(&strict_ser).unwrap();
    assert_eq!(&public_offer, &res);
}

#[test]
fn get_public_offer_id() {
    let hex = "46435357415001000200000080800000800800a0860100000000000800c80000000000000004000\
               a00000004000a000000010800140000000000000002210003b31a0a70343bb46f3db3768296ac50\
               27f9873921b37f852860c690063ff9e4c9000000000000000000000000000000000000000000000\
               00000000000000000000000260700";
    let res: PublicOffer<BtcXmr> =
        strict_encoding::strict_deserialize(&hex::decode(hex).unwrap()).unwrap();
    let id =
        PublicOfferId::from_str("3a466a0a0cff7bf800808653460076549621d07db78e697b9dfaebaba0ab8b33")
            .unwrap();
    assert_eq!(id, res.id());
}

#[test]
fn check_public_offer_magic_bytes() {
    let valid = "46435357415001000200000080800000800800a0860100000000000800c80000000000000004000\
                 a00000004000a000000010800140000000000000002210003b31a0a70343bb46f3db3768296ac50\
                 27f9873921b37f852860c690063ff9e4c9000000000000000000000000000000000000000000000\
                 00000000000000000000000260700";
    let pub_offer: Result<PublicOffer<BtcXmr>, consensus::Error> =
        deserialize(&hex::decode(valid).unwrap()[..]);
    assert!(pub_offer.is_ok());

    let invalid = "474353574150010002000000808000008008a08601000000000008c800000000000000040a00000\
                   0040a0000000108140000000000000002";
    let pub_offer: Result<PublicOffer<BtcXmr>, consensus::Error> =
        deserialize(&hex::decode(invalid).unwrap()[..]);
    assert!(pub_offer.is_err());
}

#[test]
fn parse_public_offer() {
    for hex in [
        "46435357415001000200000080800000800800a0860100000000000800c80000000000000004000\
         a00000004000a000000010800140000000000000002210003b31a0a70343bb46f3db3768296ac50\
         27f9873921b37f852860c690063ff9e4c9000000000000000000000000000000000000000000000\
         00000000000000000000000260700",
    ]
    .iter_mut()
    {
        let bytes = hex::decode(hex).expect("hex");
        let res: Result<PublicOffer<BtcXmr>, _> = strict_encoding::strict_deserialize(&bytes);
        assert!(res.is_ok());
    }
}
