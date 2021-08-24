use farcaster_core::swap::btcxmr::{BtcXmr, KeyManager};

use farcaster_core::blockchain::FeePriority;
use farcaster_core::bundle::{AliceParameters, BobParameters};
use farcaster_core::consensus::deserialize;
use farcaster_core::negotiation::PublicOffer;
use farcaster_core::protocol_message::{
    CommitAliceParameters, CommitBobParameters, RevealAliceParameters, RevealBobParameters,
};
use farcaster_core::role::{Alice, Bob};
use farcaster_core::swap::SwapId;

use bitcoin::Address;

use std::str::FromStr;

macro_rules! test_strict_ser {
    ($var:ident, $type:ty) => {
        let strict_ser = strict_encoding::strict_serialize(&$var).unwrap();
        let res: Result<$type, _> = strict_encoding::strict_deserialize(&strict_ser);
        assert!(res.is_ok());
    };
}

fn init_alice() -> (Alice<BtcXmr>, Bob<BtcXmr>, PublicOffer<BtcXmr>, SwapId) {
    let hex = "46435357415001000200000080800000800800a0860100000000000800c80000000000000004000\
               a00000004000a000000010800140000000000000002210003b31a0a70343bb46f3db3768296ac50\
               27f9873921b37f852860c690063ff9e4c9000000000000000000000000000000000000000000000\
               00000000000000000000000260700";

    let destination_address = Address::from_str("bc1qesgvtyx9y6lax0x34napc2m7t5zdq6s7xxwpvk")
        .expect("Parsable address")
        .into();
    let fee_politic = FeePriority::Low;
    let alice: Alice<BtcXmr> = Alice::new(destination_address, fee_politic);
    let refund_address = Address::from_str("bc1qesgvtyx9y6lax0x34napc2m7t5zdq6s7xxwpvk")
        .expect("Parsable address")
        .into();
    let bob: Bob<BtcXmr> = Bob::new(refund_address, fee_politic);

    let pub_offer: PublicOffer<BtcXmr> =
        deserialize(&hex::decode(hex).unwrap()[..]).expect("Parsable public offer");

    let swap_id = SwapId::random();

    (alice, bob, pub_offer, swap_id)
}

#[test]
fn create_alice_parameters() {
    let (alice, _, pub_offer, swap_id) = init_alice();
    let key_manager = KeyManager::new([
        32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
        9, 8, 7, 6, 5, 4, 3, 2, 1,
    ]);

    let alice_params = alice.generate_parameters(&key_manager, &pub_offer).unwrap();

    test_strict_ser!(alice_params, AliceParameters<BtcXmr>);

    let commit_alice_params =
        CommitAliceParameters::commit_to_bundle(swap_id, &key_manager, alice_params.clone());

    test_strict_ser!(commit_alice_params, CommitAliceParameters<BtcXmr>);

    let reveal_alice_params: RevealAliceParameters<BtcXmr> = (swap_id, alice_params).into();
    assert!(commit_alice_params
        .verify_with_reveal(&key_manager, reveal_alice_params.clone())
        .is_ok());

    test_strict_ser!(reveal_alice_params, RevealAliceParameters<BtcXmr>);
}

#[test]
fn create_bob_parameters() {
    let (_, bob, pub_offer, swap_id) = init_alice();

    let key_manager = KeyManager::new([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ]);

    let bob_params = bob.generate_parameters(&key_manager, &pub_offer).unwrap();

    test_strict_ser!(bob_params, BobParameters<BtcXmr>);

    let commit_bob_params =
        CommitBobParameters::commit_to_bundle(swap_id, &key_manager, bob_params.clone());

    test_strict_ser!(commit_bob_params, CommitBobParameters<BtcXmr>);

    let reveal_bob_params: RevealBobParameters<_> = (swap_id, bob_params).into();
    assert!(commit_bob_params
        .verify_with_reveal(&key_manager, reveal_bob_params.clone())
        .is_ok());

    test_strict_ser!(reveal_bob_params, RevealBobParameters<BtcXmr>);
}

#[test]
fn tampered_reveal_must_fail() {
    let (_, bob, pub_offer, swap_id) = init_alice();

    let key_manager = KeyManager::new([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ]);

    let key_manager2 = KeyManager::new([
        32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
        9, 8, 7, 6, 5, 4, 3, 2, 1,
    ]);

    let bob_params = bob.generate_parameters(&key_manager, &pub_offer).unwrap();

    // Commit to Bob first key_manager
    let commit_bob_params =
        CommitBobParameters::commit_to_bundle(swap_id, &key_manager, bob_params.clone());
    // Reveal other params
    let reveal_bob_params: RevealBobParameters<_> = (
        swap_id,
        bob.generate_parameters(&key_manager2, &pub_offer).unwrap(),
    )
        .into();
    // MUST error since we reveal other parameters
    assert!(commit_bob_params
        .verify_with_reveal(&key_manager, reveal_bob_params)
        .is_err());
}

#[test]
fn missing_commitment_in_vec() {
    let (_, bob, pub_offer, swap_id) = init_alice();

    let key_manager = KeyManager::new([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ]);

    let bob_params = bob.generate_parameters(&key_manager, &pub_offer).unwrap();
    let mut partial_params = bob_params.clone();
    // Remove the private view key
    partial_params.accordant_shared_keys = vec![];

    // Commit to Bob partial parameter, without the accordant shared view key
    let commit_bob_params =
        CommitBobParameters::commit_to_bundle(swap_id, &key_manager, partial_params);
    // Reveal all the params, with the accordant shared view key
    let reveal_bob_params: RevealBobParameters<_> = (
        swap_id,
        bob.generate_parameters(&key_manager, &pub_offer).unwrap(),
    )
        .into();
    // MUST error since we reveal params not committed
    assert!(commit_bob_params
        .verify_with_reveal(&key_manager, reveal_bob_params)
        .is_err());
}

// What if you commit in vec but you don't reveal?
