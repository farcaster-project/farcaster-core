use bitcoin::hashes::{sha256d, Hash};
use rand::prelude::*;
use std::convert::TryInto;
use std::str::FromStr;

use farcaster_core::crypto::{
    AccordantKeyId, ArbitratingKeyId, GenerateKey, GenerateSharedKey, ProveCrossGroupDleq,
    SharedKeyId, Sign,
};
use farcaster_core::monero::SHARED_VIEW_KEY_ID;
use farcaster_core::swap::btcxmr::*;
use farcaster_core::{consensus::CanonicalBytes, crypto::AccordantKeySet};

#[test]
fn create_key_manager_from_seed() {
    let seed = [0u8; 32];
    let swap_index = 0;
    KeyManager::new(seed, swap_index).expect("Can create a key manager");
}

#[test]
#[should_panic]
fn cannot_create_key_manager_with_swap_index_too_high() {
    let seed = [0u8; 32];
    let swap_index = u32::MAX;
    KeyManager::new(seed, swap_index).expect("Cannot create a key manager with index too high");
}

#[test]
fn key_manager_can_derive_arbitrating_bitcoin_keys() {
    let seed =
        hex::decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f").unwrap();
    let swap_index = 0;
    let mut key_manager =
        KeyManager::new(seed.try_into().unwrap(), swap_index).expect("Can create a key manager");
    let std_keys: Result<Vec<bitcoin::secp256k1::PublicKey>, _> = [
        ArbitratingKeyId::Lock,
        ArbitratingKeyId::Buy,
        ArbitratingKeyId::Cancel,
        ArbitratingKeyId::Refund,
        ArbitratingKeyId::Punish,
    ]
    .iter()
    .map(|key_id| {
        GenerateKey::<bitcoin::secp256k1::PublicKey, _>::get_pubkey(&mut key_manager, *key_id)
    })
    .collect();
    assert!(std_keys.is_ok());

    let extra_keys: Result<Vec<bitcoin::secp256k1::PublicKey>, _> = (0..50)
        .into_iter()
        .map(|extra_id| {
            let key_id = ArbitratingKeyId::Extra(extra_id);
            GenerateKey::<bitcoin::secp256k1::PublicKey, _>::get_pubkey(&mut key_manager, key_id)
        })
        .collect();
    assert!(extra_keys.is_ok());
}

#[test]
fn key_manager_can_derive_accordant_monero_keys() {
    let seed =
        hex::decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f").unwrap();
    let swap_index = 0;
    let mut key_manager =
        KeyManager::new(seed.try_into().unwrap(), swap_index).expect("Can create a key manager");
    let std_key = key_manager.get_pubkey(AccordantKeyId::Spend);
    assert!(std_key.is_ok());

    let extra_keys: Result<Vec<monero::PublicKey>, _> = (0..50)
        .into_iter()
        .map(|extra_id| {
            let key_id = AccordantKeyId::Extra(extra_id);
            GenerateKey::<monero::PublicKey, _>::get_pubkey(&mut key_manager, key_id)
        })
        .collect();
    assert!(extra_keys.is_ok());
}

#[test]
fn key_manager_can_derive_shared_monero_key() {
    let seed =
        hex::decode("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f").unwrap();
    let swap_index = 0;
    let mut key_manager =
        KeyManager::new(seed.try_into().unwrap(), swap_index).expect("Can create a key manager");
    let view_key: Result<monero::PrivateKey, _> =
        key_manager.get_shared_key(SharedKeyId::new(SHARED_VIEW_KEY_ID));
    assert!(view_key.is_ok());
}

#[test]
fn key_manager_can_sign_and_verify() {
    let mut rng = rand::thread_rng();
    let seed: [u8; 32] = rng.gen();
    let swap_index = 0;

    let mut key_manager = KeyManager::new(seed, swap_index).unwrap();
    let bytes = sha256d::Hash::hash("The message to sign!".as_bytes());
    let pubkey = key_manager
        .get_pubkey(ArbitratingKeyId::Lock)
        .expect("Should generate a pubkey");
    let sig = key_manager
        .sign(ArbitratingKeyId::Lock, bytes)
        .expect("Generating a signature doesn't fail");
    assert!(key_manager.verify_signature(&pubkey, bytes, &sig).is_ok());

    let wrong_pubkey = key_manager
        .get_pubkey(ArbitratingKeyId::Buy)
        .expect("Should generate a pubkey");
    assert!(key_manager
        .verify_signature(&wrong_pubkey, bytes, &sig)
        .is_err());
}

#[test]
fn key_manager_can_encrypt_sign_and_verify() {
    let mut rng = rand::thread_rng();
    let seed: [u8; 32] = rng.gen();
    let swap_index = 0;

    let mut key_manager = KeyManager::new(seed, swap_index).unwrap();

    let encryption_key = key_manager
        .get_encryption_key()
        .expect("Generate encryption key");

    let bytes = sha256d::Hash::hash("The message to sign!".as_bytes());
    let pubkey = key_manager
        .get_pubkey(ArbitratingKeyId::Buy)
        .expect("Should generate a pubkey");
    let enc_sig = key_manager
        .encrypt_sign(ArbitratingKeyId::Buy, &encryption_key, bytes)
        .expect("Generating a signature doesn't fail");
    assert!(key_manager
        .verify_encrypted_signature(&pubkey, &encryption_key, bytes, &enc_sig)
        .is_ok());

    let wrong_pubkey = key_manager
        .get_pubkey(ArbitratingKeyId::Punish)
        .expect("Should generate a pubkey");
    assert!(key_manager
        .verify_encrypted_signature(&wrong_pubkey, &encryption_key, bytes, &enc_sig)
        .is_err());
}

#[test]
fn key_manager_can_recover_secret() {
    let mut rng = rand::thread_rng();
    let seed: [u8; 32] = rng.gen();
    let swap_index = 0;

    let mut key_manager = KeyManager::new(seed, swap_index).unwrap();

    // Get the secret as a Monero secret key
    let secret: monero::PrivateKey = key_manager
        .get_or_derive_monero_key(AccordantKeyId::Spend)
        .expect("Should generate secret spend");
    // Get the equivalent secret projected over Bitcoin curve
    let encryption_key = key_manager
        .get_encryption_key()
        .expect("Generate encryption key");

    let bytes = sha256d::Hash::hash("The message to sign!".as_bytes());
    let enc_sig = key_manager
        .encrypt_sign(ArbitratingKeyId::Buy, &encryption_key, bytes)
        .expect("Generating a signature doesn't fail");
    let decrypt_sig = key_manager
        .decrypt_signature(AccordantKeyId::Spend, enc_sig.clone())
        .unwrap();
    let pubkey = key_manager
        .get_pubkey(ArbitratingKeyId::Buy)
        .expect("Should generate a pubkey");
    assert!(key_manager
        .verify_signature(&pubkey, bytes, &decrypt_sig)
        .is_ok());

    let recovered_secret: bitcoin::secp256k1::SecretKey =
        key_manager.recover_secret_key(enc_sig, &encryption_key, decrypt_sig);

    // check equality on canonical bytes
    let mut secret = secret.as_canonical_bytes();
    secret.reverse();
    assert_eq!(secret, recovered_secret.as_canonical_bytes());
}

#[test]
fn can_create_accordant_address() {
    use farcaster_core::crypto::{AccordantKeys, TaggedElement};
    use farcaster_core::monero::Monero;
    use farcaster_core::role::Accordant;
    use monero::{Address, Network, PrivateKey, PublicKey};

    let swap_index = 0;
    let mut alice_key_manager = KeyManager::new([1u8; 32], swap_index).unwrap();
    let mut bob_key_manager = KeyManager::new([2u8; 32], swap_index).unwrap();

    let alice_spend_pubkey = alice_key_manager.get_pubkey(AccordantKeyId::Spend).unwrap();
    let bob_spend_pubkey = bob_key_manager.get_pubkey(AccordantKeyId::Spend).unwrap();

    let alice_view_secretkey: PrivateKey = alice_key_manager
        .get_shared_key(SharedKeyId::new(SHARED_VIEW_KEY_ID))
        .unwrap();
    let bob_view_secretkey: PrivateKey = bob_key_manager
        .get_shared_key(SharedKeyId::new(SHARED_VIEW_KEY_ID))
        .unwrap();

    let public_spend = alice_spend_pubkey + bob_spend_pubkey;
    let secret_view = alice_view_secretkey + bob_view_secretkey;
    let public_view = PublicKey::from_private_key(&secret_view);

    let accordant_address = Address::standard(Network::Stagenet, public_spend, public_view);
    let addr = "52WfVg2J3fwjoUiobvJ6zXB2JL7MZsPRPTgzhVjFdZJb6afRPaeN1ND4e4MWz55Q2JM3bQLTWmMgyjPZZHLa4X587UVajzG";
    assert_eq!(Address::from_str(addr), Ok(accordant_address));

    // redo process like manual above, but test against result from Monero's derive_lock_address implementation
    let lock_address = Monero::derive_lock_address(
        farcaster_core::blockchain::Network::Testnet,
        AccordantKeySet {
            alice: AccordantKeys {
                spend_key: alice_spend_pubkey,
                shared_keys: vec![TaggedElement::new(
                    SharedKeyId::new(SHARED_VIEW_KEY_ID),
                    alice_view_secretkey,
                )],
                extra_accordant_keys: vec![],
            },
            bob: AccordantKeys {
                spend_key: bob_spend_pubkey,
                shared_keys: vec![TaggedElement::new(
                    SharedKeyId::new(SHARED_VIEW_KEY_ID),
                    bob_view_secretkey,
                )],
                extra_accordant_keys: vec![],
            },
        },
    );
    assert_eq!(
        lock_address.expect("derivation of lock address should work since manual does"),
        accordant_address
    );
}
