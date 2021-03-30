use farcaster_chains::bitcoin::fee::SatPerVByte;
use farcaster_core::blockchain::*;
use farcaster_core::script::*;
use farcaster_core::transaction::*;

use farcaster_chains::bitcoin::transaction::*;
use farcaster_chains::bitcoin::*;

//use bitcoin::consensus::encode::serialize_hex;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::key::{PrivateKey, PublicKey};

use bitcoincore_rpc::{Auth, Client, RpcApi};

fn setup() -> Result<Client, bitcoincore_rpc::Error> {
    Client::new(
        "http://127.0.0.1:18443".into(),
        Auth::UserPass(
            "test".into(),
            "cEl2o3tHHgzYeuu3CiiZ2FjdgSiw9wNeMFzoNbFmx9k=".into(),
        ),
    )
}

#[test]
#[ignore]
fn create_funding_generic() {
    let client = setup().unwrap();

    let secp = Secp256k1::new();

    let privkey_a: PrivateKey =
        PrivateKey::from_wif("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D").unwrap();
    let pubkey_a = PublicKey::from_private_key(&secp, &privkey_a);

    let privkey_b: PrivateKey =
        PrivateKey::from_wif("Kwe6eTweXYHsWX1yazBBCqB2eBSnqK6m8BPBvpJmv5pmuWi8nx1w").unwrap();
    let pubkey_b = PublicKey::from_private_key(&secp, &privkey_b);

    let privkey_a2: PrivateKey =
        PrivateKey::from_wif("Kx9uWX33oa5TbCc7Mo7vCM7yN75mehEw9aSkAeqJdC2kd1YKuKXR").unwrap();
    let pubkey_a2 = PublicKey::from_private_key(&secp, &privkey_a2);

    let privkey_b2: PrivateKey =
        PrivateKey::from_wif("L3ienZ4Zg1EP2HiiqsWih1Wkr3yuKJwTV5svqGMry1dYdrXQED8Q").unwrap();
    let pubkey_b2 = PublicKey::from_private_key(&secp, &privkey_b2);

    let mut funding = Funding::initialize(pubkey_a, Network::Local).unwrap();
    let address = funding.get_address().unwrap();

    let blocks = client.generate_to_address(1, &address).unwrap();

    let block_hash = blocks[0];
    let block = client.get_block(&block_hash).unwrap();
    let funding_tx_seen = block.coinbase().unwrap().clone();

    //println!("{:#?}", &funding_tx_seen);
    funding.update(funding_tx_seen).unwrap();

    let datalock = DataLock {
        timelock: CSVTimelock::new(10),
        success: DoubleKeys::new(pubkey_a, pubkey_b),
        failure: DoubleKeys::new(pubkey_a2, pubkey_b2),
    };

    let fee = FeeStrategy::Fixed(SatPerVByte::from_sat(50));
    let politic = FeePolitic::Aggressive;

    //println!("{:#?}", funding);
    let mut lock = Tx::<Lock>::initialize(&funding, datalock.clone(), &fee, politic).unwrap();
    //println!("{:#?}", &lock);
    //println!("{:#?}", &lock.get_consumable_output());

    //
    // Create cancel tx
    //
    let datapunishablelock = DataPunishableLock {
        timelock: CSVTimelock::new(10),
        success: DoubleKeys::new(pubkey_a, pubkey_b),
        failure: pubkey_a2,
    };
    let mut cancel =
        Tx::<Cancel>::initialize(&lock, datalock, datapunishablelock.clone(), &fee, politic)
            .unwrap();
    //println!("{:#?}", &cancel);

    //
    // Create refund tx
    //
    let new_address = {
        use bitcoin::network::constants::Network;
        use bitcoin::secp256k1::rand::thread_rng;
        use bitcoin::secp256k1::Secp256k1;
        use bitcoin::util::address::Address;
        use bitcoin::util::key;

        // Generate random key pair
        let s = Secp256k1::new();
        let public_key = key::PublicKey {
            compressed: true,
            key: s.generate_keypair(&mut thread_rng()).1,
        };

        // Generate pay-to-pubkey-hash address
        Address::p2pkh(&public_key, Network::Regtest)
    };
    let _refund =
        Tx::<Refund>::initialize(&cancel, datapunishablelock, new_address, &fee, politic).unwrap();

    //
    // Co-Sign refund
    //
    let _sig = cancel.generate_failure_witness(&privkey_a2).unwrap();
    let _sig = cancel.generate_failure_witness(&privkey_b2).unwrap();
    //println!("{:#?}", &cancel);

    //
    // Finalize for failure path
    //
    cancel.finalize().unwrap();
    let cancel_finalized = cancel.extract();

    //
    // Sign lock tx
    //
    let _sig = lock.generate_witness(&privkey_a).unwrap();
    let lock_finalized = lock.extract();
    //println!("{:#?}", &lock);

    // Generate 10 blocks to unlock the money
    // don't use `generate` as it is not available anymore
    client.generate_to_address(100, &address).unwrap();

    // Broadcast the lock
    client.send_raw_transaction(&lock_finalized).unwrap();
    // Mine the transaction
    client.generate_to_address(10, &address).unwrap();

    // Broadcast the cancel
    client.send_raw_transaction(&cancel_finalized).unwrap();
    // Mine the transaction
    client.generate_to_address(1, &address).unwrap();

    assert!(true);
}
