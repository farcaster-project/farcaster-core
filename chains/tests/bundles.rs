use farcaster_chains::pairs::btcxmr::BtcXmr;

use farcaster_core::blockchain::FeePolitic;
use farcaster_core::consensus::deserialize;
use farcaster_core::negotiation::PublicOffer;
use farcaster_core::protocol_message::{CommitAliceParameters, RevealAliceParameters};
use farcaster_core::role::Alice;

use bitcoin::Address;

use std::str::FromStr;

#[test]
fn create_alice_parameters() {
    let hex = "46435357415001000200000080800000800800a0860100000000000800c80000000000000004000\
               a00000004000a00000001080014000000000000000203b31a0a70343bb46f3db3768296ac5027f9\
               873921b37f852860c690063ff9e4c90000000000000000000000000000000000000000000000000\
               000000000000000000000260700";

    let destination_address = Address::from_str("bc1qesgvtyx9y6lax0x34napc2m7t5zdq6s7xxwpvk")
        .expect("Parsable address")
        .into();
    let fee_politic = FeePolitic::Aggressive;
    let alice: Alice<BtcXmr> = Alice::new(destination_address, fee_politic);

    let ar_seed = [
        32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
        9, 8, 7, 6, 5, 4, 3, 2, 1,
    ];
    let ac_seed = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];

    let pub_offer: PublicOffer<BtcXmr> =
        deserialize(&hex::decode(hex).unwrap()[..]).expect("Parsable public offer");

    let alice_params = dbg!(alice.generate_parameters(&ar_seed, &ac_seed, &pub_offer));

    let commit_alice_params = dbg!(CommitAliceParameters::from_bundle(&alice_params));

    let reveal_alice_params = dbg!(RevealAliceParameters::from_bundle(&alice_params).unwrap());

    assert!(dbg!(commit_alice_params.verify_then_bundle(&reveal_alice_params)).is_ok());

    //assert!(false);
}
