use bitcoin::hashes::{sha256d, Hash};
use rand::prelude::*;

use farcaster_core::consensus::CanonicalBytes;
use farcaster_core::crypto::{
    AccordantKeyId, ArbitratingKeyId, GenerateKey, ProveCrossGroupDleq, Sign,
};
use farcaster_core::swap::btcxmr::*;

#[test]
fn key_manager_and_recover_secret() {
    let mut rng = rand::thread_rng();
    let seed: [u8; 32] = rng.gen();

    let mut key_manager = KeyManager::new(seed, 1).unwrap();
    let buy_pubkey = key_manager
        .get_pubkey(ArbitratingKeyId::Buy)
        .expect("Should generate correct pubkey");
    let (_, btc_encryption_key, _) = key_manager
        .generate_proof()
        .expect("Considered valid in tests");
    let secret_spend = key_manager
        .get_or_derive_monero_key(&AccordantKeyId::Spend)
        .expect("Should generate secret spend");

    let bytes = sha256d::Hash::hash("The message to sign!".as_bytes());

    let sig = key_manager
        .sign(ArbitratingKeyId::Buy, bytes)
        .expect("Generating a signature don't fail");
    assert!(key_manager
        .verify_signature(&buy_pubkey, bytes, &sig)
        .is_ok());

    let adaptor_sig = key_manager
        .encrypt_sign(ArbitratingKeyId::Buy, &btc_encryption_key, bytes)
        .unwrap();
    assert!(key_manager
        .verify_encrypted_signature(&buy_pubkey, &btc_encryption_key, bytes, &adaptor_sig)
        .is_ok());
    let adapted_sig = key_manager
        .decrypt_signature(AccordantKeyId::Spend, adaptor_sig.clone())
        .unwrap();

    let recovered_key =
        key_manager.recover_secret_key(adaptor_sig, &btc_encryption_key, adapted_sig);
    // check equality on canonical bytes
    assert_eq!(
        secret_spend.as_canonical_bytes(),
        recovered_key.as_canonical_bytes()
    );
}
