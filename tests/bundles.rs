use farcaster_core::chain::pairs::btcxmr::{BtcXmr, Wallet};

use farcaster_core::blockchain::FeePolitic;
use farcaster_core::consensus::deserialize;
use farcaster_core::negotiation::PublicOffer;
use farcaster_core::protocol_message::{
    CommitAliceParameters, CommitBobParameters, RevealAliceParameters, RevealBobParameters,
};
use farcaster_core::role::{Alice, Bob};

use bitcoin::Address;

use std::str::FromStr;

macro_rules! test_strict_ser {
    ($var:ident, $type:ty) => {
        let strict_ser = strict_encoding::strict_serialize(&$var).unwrap();
        let res: Result<$type, _> = strict_encoding::strict_deserialize(&strict_ser);
        assert!(res.is_ok());
    };
}

fn init_alice() -> (Alice<BtcXmr>, Bob<BtcXmr>, PublicOffer<BtcXmr>) {
    let hex = "46435357415001000200000080800000800800a0860100000000000800c80000000000000004000\
               a00000004000a00000001080014000000000000000203b31a0a70343bb46f3db3768296ac5027f9\
               873921b37f852860c690063ff9e4c90000000000000000000000000000000000000000000000000\
               000000000000000000000260700";

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

    (alice, bob, pub_offer)
}

#[test]
fn create_alice_parameters() {
    let (alice, _, pub_offer) = init_alice();
    let wallet = Wallet::new([
        32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
        9, 8, 7, 6, 5, 4, 3, 2, 1,
    ]);

    let alice_params = dbg!(alice.generate_parameters(&wallet, &pub_offer).unwrap());

    let commit_alice_params = dbg!(CommitAliceParameters::commit_to_bundle(
        &wallet,
        alice_params.clone()
    ));

    test_strict_ser!(commit_alice_params, CommitAliceParameters<BtcXmr>);

    let reveal_alice_params: RevealAliceParameters<BtcXmr> = dbg!(alice_params.into());
    assert!(
        dbg!(commit_alice_params.verify_with_reveal(&wallet, reveal_alice_params.clone())).is_ok()
    );

    test_strict_ser!(reveal_alice_params, RevealAliceParameters<BtcXmr>);
}

#[test]
fn create_bob_parameters() {
    let (_, bob, pub_offer) = init_alice();

    let wallet = Wallet::new([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ]);

    let bob_params = dbg!(bob.generate_parameters(&wallet, &pub_offer).unwrap());

    let commit_bob_params = dbg!(CommitBobParameters::commit_to_bundle(
        &wallet,
        bob_params.clone()
    ));

    test_strict_ser!(commit_bob_params, CommitBobParameters<BtcXmr>);

    let reveal_bob_params: RevealBobParameters<_> = dbg!(bob_params.into());
    assert!(dbg!(commit_bob_params.verify_with_reveal(&wallet, reveal_bob_params.clone())).is_ok());

    test_strict_ser!(reveal_bob_params, RevealBobParameters<BtcXmr>);
}

#[test]
fn tampered_reveal_must_fail() {
    let (_, bob, pub_offer) = init_alice();

    let wallet = Wallet::new([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ]);

    let wallet2 = Wallet::new([
        32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
        9, 8, 7, 6, 5, 4, 3, 2, 1,
    ]);

    let bob_params = dbg!(bob.generate_parameters(&wallet, &pub_offer).unwrap());

    // Commit to Bob first wallet
    let commit_bob_params = dbg!(CommitBobParameters::commit_to_bundle(
        &wallet,
        bob_params.clone()
    ));
    // Reveal other params
    let reveal_bob_params: RevealBobParameters<_> = dbg!(bob
        .generate_parameters(&wallet2, &pub_offer)
        .unwrap()
        .into());
    // MUST error since we reveal other parameters
    assert!(dbg!(commit_bob_params.verify_with_reveal(&wallet, reveal_bob_params)).is_err());
}

#[test]
fn missing_commitment_in_vec() {
    let (_, bob, pub_offer) = init_alice();

    let wallet = Wallet::new([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ]);

    let bob_params = dbg!(bob.generate_parameters(&wallet, &pub_offer).unwrap());
    let mut partial_params = bob_params.clone();
    // Remove the private view key
    partial_params.accordant_shared_keys = vec![];

    // Commit to Bob partial parameter, without the accordant shared view key
    let commit_bob_params = dbg!(CommitBobParameters::commit_to_bundle(
        &wallet,
        partial_params
    ));
    // Reveal all the params, with the accordant shared view key
    let reveal_bob_params: RevealBobParameters<_> =
        dbg!(bob.generate_parameters(&wallet, &pub_offer).unwrap().into());
    // MUST error since we reveal params not committed
    assert!(dbg!(commit_bob_params.verify_with_reveal(&wallet, reveal_bob_params)).is_err());
}

// What if you commit in vec but you don't reveal?
