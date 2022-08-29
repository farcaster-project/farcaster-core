// Copyright 2021-2022 Farcaster Devs
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

use farcaster_core::bitcoin::fee::SatPerVByte;
use farcaster_core::bitcoin::timelock::CSVTimelock;
use farcaster_core::blockchain::Blockchain;

use farcaster_core::blockchain::{FeeStrategy, Network};
use farcaster_core::consensus::{self, deserialize, serialize_hex};
use farcaster_core::role::SwapRole;
use farcaster_core::trade::{Deal, DealFingerprint, DealParameters};

use bitcoin::Amount;
use inet2_addr::InetSocketAddr;
use uuid::uuid;

use std::str::FromStr;

#[test]
fn create_trade() {
    let hex = "4450e567b1106f429247bb680e5fe0c802000000808000008008000500000000000000080006000000000000000400070000000400080000000\
               10800090000000000000002";
    let trade: DealParameters<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte> =
        DealParameters {
            uuid: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
            network: Network::Testnet,
            arbitrating_blockchain: Blockchain::Bitcoin,
            accordant_blockchain: Blockchain::Monero,
            arbitrating_amount: Amount::from_sat(5),
            accordant_amount: monero::Amount::from_pico(6),
            cancel_timelock: CSVTimelock::new(7),
            punish_timelock: CSVTimelock::new(8),
            fee_strategy: FeeStrategy::Fixed(SatPerVByte::from_sat(9)),
            maker_role: SwapRole::Bob,
        };

    assert_eq!(hex, serialize_hex(&trade));
    let strict_ser = strict_encoding::strict_serialize(&trade).unwrap();
    assert_eq!(&hex::decode(hex).unwrap(), &strict_ser);
    let res: DealParameters<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte> =
        strict_encoding::strict_deserialize(&strict_ser).unwrap();
    assert_eq!(&trade, &res);
}

#[test]
fn get_trade_fingerprint() {
    let hex = "4450e567b1106f429247bb680e5fe0c802000000808000008008000500000000000000080006000\
               00000000000040007000000040008000000010800090000000000000002";
    let res: DealParameters<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte> =
        strict_encoding::strict_deserialize(&hex::decode(hex).unwrap()).unwrap();
    let id = DealFingerprint::from_str(
        "f79b29ccb233b37cea3aa35b94c5ece25c58a8098afc18f046810a3c04591599",
    )
    .unwrap();
    assert_eq!(id, res.fingerprint());
    // other uuid
    let hex = "4351e567b1106f429247bb680e5fe0c802000000808000008008000500000000000000080006000\
               00000000000040007000000040008000000010800090000000000000002";
    let res: DealParameters<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte> =
        strict_encoding::strict_deserialize(&hex::decode(hex).unwrap()).unwrap();
    // same fingerprint
    assert_eq!(id, res.fingerprint());
}

#[test]
fn get_trade_uuid() {
    let hex = "4450e567b1106f429247bb680e5fe0c802000000808000008008000500000000000000080006000\
               00000000000040007000000040008000000010800090000000000000002";
    let res: DealParameters<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte> =
        strict_encoding::strict_deserialize(&hex::decode(hex).unwrap()).unwrap();
    assert_eq!(uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"), res.uuid());
}

#[test]
fn serialize_public_trade() {
    let hex = "46435357415001004450e567b1106f429247bb680e5fe0c80200000080800000800800a08601000\
               00000000800c80000000000000004000a00000004000a0000000108001400000000000000022100\
               03b31a0a70343bb46f3db3768296ac5027f9873921b37f852860c690063ff9e4c90000000000000\
               0000000000000000000000000000000000000000000000000000000260700";
    let trade: DealParameters<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte> =
        DealParameters {
            uuid: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
            network: Network::Testnet,
            arbitrating_blockchain: Blockchain::Bitcoin,
            accordant_blockchain: Blockchain::Monero,
            arbitrating_amount: Amount::from_sat(100000),
            accordant_amount: monero::Amount::from_pico(200),
            cancel_timelock: CSVTimelock::new(10),
            punish_timelock: CSVTimelock::new(10),
            fee_strategy: FeeStrategy::Fixed(SatPerVByte::from_sat(20)),
            maker_role: SwapRole::Bob,
        };
    let ip = FromStr::from_str("0.0.0.0").unwrap();
    let port = FromStr::from_str("9735").unwrap();

    let secp = secp256k1::Secp256k1::new();
    let sk = bitcoin::util::key::PrivateKey::from_wif(
        "L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D",
    )
    .unwrap()
    .inner;
    let node_id = secp256k1::PublicKey::from_secret_key(&secp, &sk);
    let peer_address = InetSocketAddr::socket(ip, port);
    let public_trade = trade.to_v1(node_id, peer_address);

    assert_eq!(hex, serialize_hex(&public_trade));
    let strict_ser = strict_encoding::strict_serialize(&public_trade).unwrap();
    assert_eq!(&hex::decode(hex).unwrap(), &strict_ser);
    let res: Deal<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte> =
        strict_encoding::strict_deserialize(&strict_ser).unwrap();
    assert_eq!(&public_trade, &res);
}

#[test]
fn get_public_trade_fingerprint() {
    let hex = "46435357415001004450e567b1106f429247bb680e5fe0c80200000080800000800800a08601000\
               00000000800c80000000000000004000a00000004000a0000000108001400000000000000022100\
               03b31a0a70343bb46f3db3768296ac5027f9873921b37f852860c690063ff9e4c90000000000000\
               0000000000000000000000000000000000000000000000000000000260700";
    let res: Deal<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte> =
        strict_encoding::strict_deserialize(&hex::decode(hex).unwrap()).unwrap();
    let id = DealFingerprint::from_str(
        "3a466a0a0cff7bf800808653460076549621d07db78e697b9dfaebaba0ab8b33",
    )
    .unwrap();
    assert_eq!(id, res.fingerprint());
    // other uuid
    let hex = "46435357415001004754e567b1206f429247bb680e5fe0c80200000080800000800800a08601000\
               00000000800c80000000000000004000a00000004000a0000000108001400000000000000022100\
               03b31a0a70343bb46f3db3768296ac5027f9873921b37f852860c690063ff9e4c90000000000000\
               0000000000000000000000000000000000000000000000000000000260700";
    let res: Deal<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte> =
        strict_encoding::strict_deserialize(&hex::decode(hex).unwrap()).unwrap();
    // same fingerprint
    assert_eq!(id, res.fingerprint());
}

#[test]
fn get_public_trade_uuid() {
    let hex = "46435357415001004450e567b1106f429247bb680e5fe0c80200000080800000800800a08601000\
               00000000800c80000000000000004000a00000004000a0000000108001400000000000000022100\
               03b31a0a70343bb46f3db3768296ac5027f9873921b37f852860c690063ff9e4c90000000000000\
               0000000000000000000000000000000000000000000000000000000260700";
    let res: Deal<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte> =
        strict_encoding::strict_deserialize(&hex::decode(hex).unwrap()).unwrap();
    assert_eq!(uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"), res.uuid());
}

#[test]
fn check_public_trade_magic_bytes() {
    let valid = "46435357415001004450e567b1106f429247bb680e5fe0c80200000080800000800800a08601000\
                 00000000800c80000000000000004000a00000004000a0000000108001400000000000000022100\
                 03b31a0a70343bb46f3db3768296ac5027f9873921b37f852860c690063ff9e4c90000000000000\
                 0000000000000000000000000000000000000000000000000000000260700";
    let pub_trade: Result<
        Deal<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte>,
        consensus::Error,
    > = deserialize(&hex::decode(valid).unwrap()[..]);
    assert!(pub_trade.is_ok());

    let invalid = "47435357415001004450e567b1106f429247bb680e5fe0c80200000080800000800800a08601000\
                 00000000800c80000000000000004000a00000004000a0000000108001400000000000000022100\
                 03b31a0a70343bb46f3db3768296ac5027f9873921b37f852860c690063ff9e4c90000000000000\
                 0000000000000000000000000000000000000000000000000000000260700";
    let pub_trade: Result<
        Deal<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte>,
        consensus::Error,
    > = deserialize(&hex::decode(invalid).unwrap()[..]);
    assert!(pub_trade.is_err());
}

#[test]
fn parse_public_trade() {
    for hex in [
        "46435357415001004450e567b1106f429247bb680e5fe0c80200000080800000800800a08601000\
         00000000800c80000000000000004000a00000004000a0000000108001400000000000000022100\
         03b31a0a70343bb46f3db3768296ac5027f9873921b37f852860c690063ff9e4c90000000000000\
         0000000000000000000000000000000000000000000000000000000260700",
    ]
    .iter_mut()
    {
        let bytes = hex::decode(hex).expect("hex");
        let res: Result<Deal<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte>, _> =
            strict_encoding::strict_deserialize(&bytes);
        assert!(res.is_ok());
    }
}
