use farcaster_core::bitcoin::segwitv0::FundingTx;
use farcaster_core::swap::btcxmr::{BtcXmr, KeyManager};

use farcaster_core::blockchain::{FeePriority, Network};
use farcaster_core::consensus::deserialize;
use farcaster_core::crypto::{ArbitratingKeyId, GenerateKey};
use farcaster_core::negotiation::PublicOffer;
use farcaster_core::protocol_message::{
    CommitAliceParameters, CommitBobParameters, RevealAliceParameters, RevealBobParameters,
};
use farcaster_core::role::{Alice, Bob};
use farcaster_core::swap::SwapId;
use farcaster_core::transaction::Fundable;

use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
use bitcoin::{Address, Transaction};

use std::str::FromStr;

fn init() -> (Alice<BtcXmr>, Bob<BtcXmr>, PublicOffer<BtcXmr>) {
    let hex = "46435357415001000200000080800000800800a0860100000000000800c80000000000000004000\
               a00000004000a000000010800140000000000000002210003b31a0a70343bb46f3db3768296ac50\
               27f9873921b37f852860c690063ff9e4c9000000000000000000000000000000000000000000000\
               00000000000000000000000260700";

    let destination_address =
        Address::from_str("bc1qesgvtyx9y6lax0x34napc2m7t5zdq6s7xxwpvk").expect("Parsable address");
    let fee_politic = FeePriority::Low;
    let alice: Alice<BtcXmr> = Alice::new(destination_address, fee_politic);
    let refund_address =
        Address::from_str("bc1qesgvtyx9y6lax0x34napc2m7t5zdq6s7xxwpvk").expect("Parsable address");
    let bob: Bob<BtcXmr> = Bob::new(refund_address, fee_politic);

    let pub_offer: PublicOffer<BtcXmr> =
        deserialize(&hex::decode(hex).unwrap()[..]).expect("Parsable public offer");

    (alice, bob, pub_offer)
}

#[test]
fn execute_offline_protocol() {
    let (alice, bob, pub_offer) = init();

    let alice_key_manager = KeyManager::new([
        32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
        9, 8, 7, 6, 5, 4, 3, 2, 1,
    ]);

    let bob_key_manager = KeyManager::new([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ]);

    let swap_id = SwapId::random();

    //
    // Commit/Reveal round
    //
    let alice_params = alice
        .generate_parameters(&alice_key_manager, &pub_offer)
        .unwrap();
    let commit_alice_params =
        CommitAliceParameters::commit_to_bundle(swap_id, &alice_key_manager, alice_params.clone());

    let bob_params = bob
        .generate_parameters(&bob_key_manager, &pub_offer)
        .unwrap();
    let commit_bob_params =
        CommitBobParameters::commit_to_bundle(swap_id, &bob_key_manager, bob_params.clone());

    // Reveal
    let reveal_alice_params: RevealAliceParameters<BtcXmr> = (swap_id, alice_params.clone()).into();
    let reveal_bob_params: RevealBobParameters<BtcXmr> = (swap_id, bob_params.clone()).into();

    assert!(commit_alice_params
        .verify_with_reveal(&bob_key_manager, reveal_alice_params)
        .is_ok());
    assert!(commit_bob_params
        .verify_with_reveal(&alice_key_manager, reveal_bob_params)
        .is_ok());

    //
    // Get Funding Address and Transaction
    //
    let funding_key = bob_key_manager.get_pubkey(ArbitratingKeyId::Fund).unwrap();
    let mut funding = FundingTx::initialize(funding_key, Network::Local).unwrap();
    let funding_address = funding.get_address().unwrap();

    let funding_tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::blockdata::script::Script::default(),
            sequence: (1 << 31) as u32, // activate disable flag on CSV
            witness: vec![],
        }],
        output: vec![TxOut {
            value: 123456789,
            script_pubkey: funding_address.script_pubkey(),
        }],
    };

    funding.update(funding_tx).unwrap();

    //
    // Create core arb transactions
    //
    let core = bob
        .core_arbitrating_transactions(&alice_params, &bob_params, funding, &pub_offer)
        .unwrap();
    let _bob_cosign_cancel = bob
        .cosign_arbitrating_cancel(&bob_key_manager, &bob_params, &core)
        .unwrap();

    let adaptor_refund = alice
        .sign_adaptor_refund(
            &alice_key_manager,
            &alice_params,
            &bob_params,
            &core,
            &pub_offer,
        )
        .unwrap();
    let _alice_cosign_cancel = alice
        .cosign_arbitrating_cancel(
            &alice_key_manager,
            &alice_params,
            &bob_params,
            &core,
            &pub_offer,
        )
        .unwrap();

    bob.validate_adaptor_refund(
        &bob_key_manager,
        &alice_params,
        &bob_params,
        &core,
        &adaptor_refund,
    )
    .unwrap();
    let adaptor_buy = bob
        .sign_adaptor_buy(
            &bob_key_manager,
            &alice_params,
            &bob_params,
            &core,
            &pub_offer,
        )
        .unwrap();
    let _signed_lock = bob
        .sign_arbitrating_lock(&bob_key_manager, &bob_key_manager, &core)
        .unwrap();

    alice
        .validate_adaptor_buy(
            &alice_key_manager,
            &alice_params,
            &bob_params,
            &core,
            &pub_offer,
            &adaptor_buy,
        )
        .unwrap();
    let _fully_sign_buy = alice
        .fully_sign_buy(
            &alice_key_manager,
            &alice_params,
            &bob_params,
            &core,
            &pub_offer,
            &adaptor_buy,
        )
        .unwrap();
}
