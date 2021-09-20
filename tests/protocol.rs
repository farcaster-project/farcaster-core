use farcaster_core::bitcoin::{
    segwitv0::{BuyTx, CancelTx, FundingTx, LockTx, PunishTx, RefundTx},
    BitcoinSegwitV0,
};
use farcaster_core::swap::btcxmr::{BtcXmr, KeyManager};

use farcaster_core::blockchain::{FeePriority, Network};
use farcaster_core::consensus::deserialize;
use farcaster_core::crypto::{
    ArbitratingKeyId, CommitmentEngine, GenerateKey, ProveCrossGroupDleq,
};
use farcaster_core::negotiation::PublicOffer;
use farcaster_core::protocol_message::*;
use farcaster_core::role::{Alice, Bob};
use farcaster_core::swap::SwapId;
use farcaster_core::transaction::*;

use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use bitcoin::Address;

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

    let commitment_engine = CommitmentEngine;
    let mut alice_key_manager = KeyManager::new(
        [
            32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
            10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
        ],
        1,
    )
    .unwrap();

    let mut bob_key_manager = KeyManager::new(
        [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ],
        1,
    )
    .unwrap();

    let swap_id = SwapId::random();

    //
    // Commit/Reveal round
    //
    let alice_params = alice
        .generate_parameters(&mut alice_key_manager, &pub_offer)
        .unwrap();
    let commit_alice_params =
        CommitAliceParameters::commit_to_bundle(swap_id, &commitment_engine, alice_params.clone());

    let bob_params = bob
        .generate_parameters(&mut bob_key_manager, &pub_offer)
        .unwrap();
    let commit_bob_params =
        CommitBobParameters::commit_to_bundle(swap_id, &commitment_engine, bob_params.clone());

    // Reveal
    let reveal_alice_params: RevealAliceParameters<BtcXmr> = (swap_id, alice_params.clone()).into();
    let reveal_bob_params: RevealBobParameters<BtcXmr> = (swap_id, bob_params.clone()).into();

    assert!(commit_alice_params
        .verify_with_reveal(&commitment_engine, reveal_alice_params)
        .is_ok());
    assert!(commit_bob_params
        .verify_with_reveal(&commitment_engine, reveal_bob_params)
        .is_ok());

    //
    // Get Funding Address and Transaction
    //
    let funding_key = bob_key_manager.get_pubkey(ArbitratingKeyId::Fund).unwrap();
    let mut funding = FundingTx::initialize(funding_key, Network::Local).unwrap();
    let funding_address = funding.get_address().unwrap();

    let funding_tx = bitcoin::Transaction {
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
    let bob_cosign_cancel = bob
        .cosign_arbitrating_cancel(&mut bob_key_manager, &core)
        .unwrap();

    let _: CoreArbitratingSetup<BtcXmr> = (swap_id, core.clone(), bob_cosign_cancel.clone()).into();

    //
    // Sign the refund procedure
    //
    let adaptor_refund = alice
        .sign_adaptor_refund(
            &mut alice_key_manager,
            &alice_params,
            &bob_params,
            &core,
            &pub_offer,
        )
        .unwrap();
    let alice_cosign_cancel = alice
        .cosign_arbitrating_cancel(
            &mut alice_key_manager,
            &alice_params,
            &bob_params,
            &core,
            &pub_offer,
        )
        .unwrap();

    let _: RefundProcedureSignatures<BtcXmr> =
        (swap_id, alice_cosign_cancel.clone(), adaptor_refund.clone()).into();

    //
    // Validate the refund procedure and sign the buy procedure
    //
    bob.validate_adaptor_refund(
        &mut bob_key_manager,
        &alice_params,
        &bob_params,
        &core,
        &adaptor_refund,
    )
    .unwrap();
    let adaptor_buy = bob
        .sign_adaptor_buy(
            &mut bob_key_manager,
            &alice_params,
            &bob_params,
            &core,
            &pub_offer,
        )
        .unwrap();
    let signed_lock = bob
        .sign_arbitrating_lock(&mut bob_key_manager, &core)
        .unwrap();

    let mut lock = LockTx::from_partial(core.lock.clone());
    lock.add_witness(funding_key, signed_lock.lock_sig).unwrap();
    let _ = Broadcastable::<BitcoinSegwitV0>::finalize_and_extract(&mut lock).unwrap();

    // ...seen arbitrating lock...
    // ...seen accordant lock...

    let _: BuyProcedureSignature<BtcXmr> = (swap_id, adaptor_buy.clone()).into();

    //
    // IF BUY PATH:
    //

    //
    // Validate the buy procedure and complete the buy
    //
    alice
        .validate_adaptor_buy(
            &mut alice_key_manager,
            &alice_params,
            &bob_params,
            &core,
            &pub_offer,
            &adaptor_buy,
        )
        .unwrap();
    let fully_sign_buy = alice
        .fully_sign_buy(
            &mut alice_key_manager,
            &alice_params,
            &bob_params,
            &core,
            &pub_offer,
            &adaptor_buy,
        )
        .unwrap();

    let mut buy = BuyTx::from_partial(adaptor_buy.buy.clone());
    buy.add_witness(bob_params.buy, fully_sign_buy.buy_adapted_sig)
        .unwrap();
    buy.add_witness(alice_params.buy, fully_sign_buy.buy_sig)
        .unwrap();
    let buy_tx = Broadcastable::<BitcoinSegwitV0>::finalize_and_extract(&mut buy).unwrap();

    // ...seen buy tx on-chain...

    let (xmr_public_spend, btc_adaptor_pubkey, _) = alice_key_manager
        .generate()
        .expect("Considered valid in tests");

    let secp = Secp256k1::new();
    let btc_adaptor_priv =
        bob.recover_accordant_assets(&mut bob_key_manager, &alice_params, adaptor_buy, buy_tx);
    let xmr_spend_priv = monero::PrivateKey::from_slice(btc_adaptor_priv.as_ref())
        .expect("Valid Monero Private Key");

    assert_eq!(
        PublicKey::from_secret_key(&secp, &btc_adaptor_priv),
        btc_adaptor_pubkey,
    );
    assert_eq!(
        monero::PublicKey::from_private_key(&xmr_spend_priv),
        xmr_public_spend,
    );

    //
    // IF CANCEL PATH:
    //

    let mut cancel = CancelTx::from_partial(core.cancel.clone());
    cancel
        .add_witness(bob_params.cancel, bob_cosign_cancel.cancel_sig)
        .unwrap();
    cancel
        .add_witness(alice_params.cancel, alice_cosign_cancel.cancel_sig)
        .unwrap();
    let _ = Broadcastable::<BitcoinSegwitV0>::finalize_and_extract(&mut cancel).unwrap();

    // ...seen arbitrating cancel...

    //
    // IF REFUND CANCEL PATH:
    //

    let fully_signed_refund = bob
        .fully_sign_refund(&mut bob_key_manager, core.clone(), &adaptor_refund)
        .unwrap();

    let mut refund = RefundTx::from_partial(core.refund.clone());
    refund
        .add_witness(alice_params.refund, fully_signed_refund.refund_adapted_sig)
        .unwrap();
    refund
        .add_witness(bob_params.refund, fully_signed_refund.refund_sig)
        .unwrap();
    let refund_tx = Broadcastable::<BitcoinSegwitV0>::finalize_and_extract(&mut refund).unwrap();

    // ...seen refund tx on-chain...

    let (xmr_public_spend, btc_adaptor_pubkey, _) = bob_key_manager
        .generate()
        .expect("Considered valid in tests");

    let btc_adaptor_priv = alice.recover_accordant_assets(
        &mut alice_key_manager,
        &bob_params,
        adaptor_refund,
        refund_tx,
    );
    let xmr_spend_priv = monero::PrivateKey::from_slice(btc_adaptor_priv.as_ref())
        .expect("Valid Monero Private Key");

    assert_eq!(
        PublicKey::from_secret_key(&secp, &btc_adaptor_priv),
        btc_adaptor_pubkey,
    );
    assert_eq!(
        monero::PublicKey::from_private_key(&xmr_spend_priv),
        xmr_public_spend,
    );

    //
    // IF PUNISH CANCEL PATH:
    //

    let fully_signed_punish = alice
        .fully_sign_punish(
            &mut alice_key_manager,
            &alice_params,
            &bob_params,
            &core,
            &pub_offer,
        )
        .unwrap();

    let mut punish = PunishTx::from_partial(fully_signed_punish.punish);
    punish
        .add_witness(alice_params.punish, fully_signed_punish.punish_sig)
        .unwrap();
    let _ = Broadcastable::<BitcoinSegwitV0>::finalize_and_extract(&mut refund).unwrap();
}
