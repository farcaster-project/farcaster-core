use farcaster_core::blockchain::*;
use farcaster_core::script::*;
use farcaster_core::transaction::*;

use farcaster_chains::bitcoin::fee::SatPerVByte;
use farcaster_chains::bitcoin::transaction::*;
use farcaster_chains::bitcoin::CSVTimelock;

use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
use bitcoin::hash_types::Txid;
use bitcoin::hashes::hex::FromHex;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::Transaction;

#[test]
fn create_funding_generic() {
    let secp = Secp256k1::new();

    let privkey: PrivateKey =
        PrivateKey::from_wif("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D").unwrap();
    let pubkey = PublicKey::from_private_key(&secp, &privkey);

    let mut funding = Funding::initialize(pubkey, Network::Mainnet).unwrap();

    let funding_tx_seen = Transaction {
        version: 1,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_hex(
                    "e567952fb6cc33857f392efa3a46c995a28f69cca4bb1b37e0204dab1ec7a389",
                )
                .unwrap(),
                vout: 1,
            },
            script_sig: Script::from_hex("160014be18d152a9b012039daf3da7de4f53349eecb985").unwrap(),
            sequence: 4294967295,
            witness: vec![Vec::from_hex(
                "03d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f2105",
            )
            .unwrap()],
        }],
        output: vec![TxOut {
            value: 10_000_000,
            script_pubkey: Script::new_v0_wpkh(&pubkey.wpubkey_hash().unwrap()),
        }],
    };
    funding.update(funding_tx_seen).unwrap();

    let datalock = DataLock {
        timelock: CSVTimelock::new(10),
        success: DoubleKeys::new(pubkey, pubkey),
        failure: DoubleKeys::new(pubkey, pubkey),
    };

    let fee = FeeStrategy::Fixed(SatPerVByte::from_sat(20));
    let politic = FeePolitic::Aggressive;

    let mut lock = Tx::<Lock>::initialize(&funding, datalock.clone(), &fee, politic).unwrap();

    let datapunishablelock = DataPunishableLock {
        timelock: CSVTimelock::new(10),
        success: DoubleKeys::new(pubkey, pubkey),
        failure: pubkey,
    };
    let cancel =
        Tx::<Cancel>::initialize(&lock, datalock, datapunishablelock.clone(), &fee, politic)
            .unwrap();

    let address = {
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
        Address::p2pkh(&public_key, Network::Bitcoin)
    };

    let _refund =
        Tx::<Refund>::initialize(&cancel, datapunishablelock, address, &fee, politic).unwrap();

    // Sign lock tx
    let _sig = lock.generate_witness(&privkey).unwrap();
    assert!(true);
}
