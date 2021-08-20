use bitcoin::hashes::{sha256d, Hash};
use rand::prelude::*;

use farcaster_core::consensus::CanonicalBytes;
use farcaster_core::crypto::{ArbitratingKeyId, GenerateKey, ProveCrossGroupDleq, Sign};
use farcaster_core::swap::btcxmr::*;

#[test]
fn key_manager_and_recover_secret() {
    let mut rng = rand::thread_rng();
    let seed: [u8; 32] = rng.gen();

    let key_manager = KeyManager::new(seed);
    let buy_pubkey = key_manager
        .get_pubkey(ArbitratingKeyId::Buy)
        .expect("Should generate correct pubkey");
    let (_, btc_adaptor_pubkey, _) = key_manager.generate().expect("Considered valid in tests");
    let secret_spend = key_manager
        .private_spend_from_seed()
        .expect("Should generate secret spend");

    let bytes = sha256d::Hash::hash("The message to sign!".as_bytes());

    let sig = key_manager
        .sign_with_key(&buy_pubkey, bytes)
        .expect("Generating a signature don't fail");
    assert!(key_manager
        .verify_signature(&buy_pubkey, bytes, &sig)
        .is_ok());

    let adaptor_sig = key_manager
        .adaptor_sign_with_key(&buy_pubkey, &btc_adaptor_pubkey, bytes)
        .unwrap();
    assert!(key_manager
        .verify_adaptor_signature(&buy_pubkey, &btc_adaptor_pubkey, bytes, &adaptor_sig)
        .is_ok());
    let adapted_sig = key_manager
        .adapt_signature(&btc_adaptor_pubkey, adaptor_sig.clone())
        .unwrap();

    let recovered_key = key_manager.recover_key(&btc_adaptor_pubkey, adapted_sig, adaptor_sig);
    // check equality on canonical bytes
    assert_eq!(
        secret_spend.as_canonical_bytes(),
        recovered_key.as_canonical_bytes()
    );
}
