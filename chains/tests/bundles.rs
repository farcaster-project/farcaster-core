use farcaster_chains::pairs::btcxmr::BtcXmr;

use farcaster_core::blockchain::FeePolitic;
use farcaster_core::consensus::deserialize;
use farcaster_core::negotiation::PublicOffer;
use farcaster_core::role::Alice;

use bitcoin::Address;

use std::str::FromStr;

#[test]
fn create_alice_params() {
    let hex = "464353574150010002000000808000008008a08601000000000008c800000000000000040a00000004\
               0a000000010814000000000000000203b31a0a70343bb46f3db3768296ac5027f9873921b37f852860\
               c690063ff9e4c900000000000000000000000000000000000000000000000000000000000000000000\
               00260700";

    let destination_address =
        Address::from_str("bc1qesgvtyx9y6lax0x34napc2m7t5zdq6s7xxwpvk").expect("Parsable address");
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

    let _alice_params = alice.session_params(&ar_seed, &ac_seed, &pub_offer);
}
