use farcaster_core::bitcoin::transaction::*;
use farcaster_core::bitcoin::*;
use farcaster_core::blockchain::*;
use farcaster_core::script::{self, *};
use farcaster_core::transaction::*;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
use bitcoin::hash_types::Txid;
use bitcoin::hashes::hex::FromHex;
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::amount::Amount;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::Transaction;

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

    let privkey: PrivateKey =
        PrivateKey::from_wif("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D").unwrap();
    let pubkey = PublicKey::from_private_key(&secp, &privkey);

    let mut funding = Funding::initialize(pubkey).unwrap();
    let address = funding.get_address(Network::Regtest).unwrap();

    //println!("Send funds to: {}", address);
    let blocks = client.generate_to_address(1, &address).unwrap();
    //println!("{:?}", blocks);

    let block_hash = blocks[0];
    let block = client.get_block(&block_hash).unwrap();
    let funding_tx_seen = block.coinbase().unwrap().clone();

    //println!("{:#?}", &funding_tx_seen);
    funding.update(funding_tx_seen).unwrap();

    let datalock = script::DataLock {
        timelock: 10,
        success: DoubleKeys::new(pubkey, pubkey),
        failure: DoubleKeys::new(pubkey, pubkey),
    };

    let fee = FeeStrategies::fixed_fee(SatPerVByte::from_sat(50));
    let politic = FeePolitic::Aggressive;

    println!("{:#?}", funding);
    let mut lock = Tx::<Lock>::initialize(&funding, datalock, &fee, politic).unwrap();
    //println!("{:#?}", lock);

    let datapunishablelock = script::DataPunishableLock {
        timelock: 10,
        success: DoubleKeys::new(pubkey, pubkey),
        failure: pubkey,
    };
    let cancel = Tx::<Cancel>::initialize(&lock, datapunishablelock, &fee, politic).unwrap();
    //println!("{:#?}", cancel);

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

    let refund = Tx::<Refund>::initialize(&cancel, new_address, &fee, politic).unwrap();

    // Sign lock tx
    let sig = lock.generate_witness(&privkey).unwrap();
    println!("{:#?}", &lock);
    let lock_finalized = lock.finalize();

    // Generate 10 blocks to unlock the money
    // don't use `generate` as it is not available anymore
    client.generate_to_address(100, &address).unwrap();

    // TODO do the other signatures

    // Broadcast the lock
    println!("{}", serialize_hex(&lock_finalized));
    client.send_raw_transaction(&lock_finalized).unwrap();

    assert!(true);
}
