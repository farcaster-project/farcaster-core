use farcaster_core::chain::bitcoin::transaction::Funding;
use farcaster_core::chain::pairs::btcxmr::{BtcXmr, Wallet};

use farcaster_core::blockchain::{FeePolitic, Network};
use farcaster_core::consensus::deserialize;
use farcaster_core::crypto::{ArbitratingKeyId, GenerateKey};
use farcaster_core::negotiation::PublicOffer;
use farcaster_core::protocol_message::{
    CommitAliceParameters, CommitBobParameters, RevealAliceParameters, RevealBobParameters,
};
use farcaster_core::role::{Alice, Bob};
use farcaster_core::transaction::Fundable;

use bitcoin::Address;

use std::str::FromStr;

fn init_alice() -> (
    Alice<BtcXmr>,
    Bob<BtcXmr>,
    PublicOffer<BtcXmr>,
    bitcoin::Transaction,
) {
    let hex = "46435357415001000200000080800000800800a0860100000000000800c80000000000000004000\
               a00000004000a00000001080014000000000000000203b31a0a70343bb46f3db3768296ac5027f9\
               873921b37f852860c690063ff9e4c90000000000000000000000000000000000000000000000000\
               000000000000000000000260700";

    let funding_tx = "020000000001010000000000000000000000000000000000000000000000000000000000\
               000000ffffffff03510101ffffffff0200f2052a0100000016001490d2e860d4e51f68857d65bfa\
               7d0da32dd6c9b350000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c\
               690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000\
               000000000000000000000000000";

    let funding_tx: bitcoin::Transaction =
        bitcoin::consensus::encode::deserialize(&hex::decode(funding_tx).unwrap()).unwrap();
    let destination_address = Address::from_str("bc1qesgvtyx9y6lax0x34napc2m7t5zdq6s7xxwpvk")
        .expect("Parsable address")
        .into();
    let fee_politic = FeePolitic::Aggressive;
    let alice: Alice<BtcXmr> = Alice::new(destination_address, fee_politic);
    let refund_address = Address::from_str("bc1qesgvtyx9y6lax0x34napc2m7t5zdq6s7xxwpvk")
        .expect("Parsable address")
        .into();
    let bob: Bob<BtcXmr> = Bob::new(refund_address, fee_politic);

    let pub_offer: PublicOffer<BtcXmr> =
        deserialize(&hex::decode(hex).unwrap()[..]).expect("Parsable public offer");

    (alice, bob, pub_offer, funding_tx)
}

#[test]
fn create_alice_parameters() {
    let (alice, bob, pub_offer, funding_tx) = init_alice();

    let alice_wallet = Wallet::new([
        32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
        9, 8, 7, 6, 5, 4, 3, 2, 1,
    ]);

    let bob_wallet = Wallet::new([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ]);

    //
    // Commit/Reveal round
    //
    let alice_params = alice
        .generate_parameters(&alice_wallet, &pub_offer)
        .unwrap();
    let commit_alice_params =
        CommitAliceParameters::commit_to_bundle(&alice_wallet, alice_params.clone());

    let bob_params = bob.generate_parameters(&bob_wallet, &pub_offer).unwrap();
    let commit_bob_params = CommitBobParameters::commit_to_bundle(&bob_wallet, bob_params.clone());

    // Reveal
    let reveal_alice_params: RevealAliceParameters<BtcXmr> = alice_params.clone().into();
    let reveal_bob_params: RevealBobParameters<BtcXmr> = bob_params.clone().into();

    assert!(commit_alice_params
        .verify_with_reveal(&bob_wallet, reveal_alice_params)
        .is_ok());
    assert!(commit_bob_params
        .verify_with_reveal(&alice_wallet, reveal_bob_params)
        .is_ok());

    //
    // Create core arb transactions
    //
    let funding_key = bob_wallet.get_pubkey(ArbitratingKeyId::Fund).unwrap();
    let mut funding = Funding::initialize(funding_key, Network::Local).unwrap();
    funding.update(funding_tx).unwrap();

    let core = bob
        .core_arbitrating_transactions(&alice_params, &bob_params, funding, &pub_offer)
        .unwrap();

    let _signed_adaptor = alice
        .sign_adaptor_refund(&alice_wallet, &alice_params, &bob_params, &core, &pub_offer)
        .unwrap();
}
