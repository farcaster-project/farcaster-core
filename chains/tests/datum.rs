use bitcoin::blockdata::transaction::{TxIn, TxOut};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::key::{PrivateKey, PublicKey};

use farcaster_chains::bitcoin::fee::SatPerVByte;
use farcaster_chains::bitcoin::transaction::{Funding, Lock, Tx};
use farcaster_chains::bitcoin::{Bitcoin, CSVTimelock};
use farcaster_chains::pairs::btcxmr::BtcXmr;

use farcaster_core::blockchain::{FeePolitic, FeeStrategy, Network};
use farcaster_core::consensus::{deserialize, serialize, serialize_hex};
use farcaster_core::datum::{self, Key};
use farcaster_core::script::{DataLock, DoubleKeys};
use farcaster_core::transaction::{Fundable, Lockable, Transaction};

#[test]
fn create_key_datum() {
    let secp = Secp256k1::new();

    let privkey: PrivateKey =
        PrivateKey::from_wif("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D").unwrap();
    let pubkey = PublicKey::from_private_key(&secp, &privkey);

    let key_datum = dbg!(Key::<BtcXmr>::new_alice_buy(pubkey));

    dbg!(serialize_hex(&key_datum));
    let bytes = dbg!(serialize(&key_datum));
    let key_datum_2: Key<BtcXmr> = dbg!(deserialize(&bytes).unwrap());

    assert_eq!(key_datum.key_id(), key_datum_2.key_id());
    assert_eq!(
        key_datum.key().try_into_arbitrating_pubkey().unwrap(),
        key_datum_2.key().try_into_arbitrating_pubkey().unwrap()
    );

    //assert!(false);
}

#[test]
fn create_transaction_datum() {
    let secp = Secp256k1::new();

    let privkey: PrivateKey =
        PrivateKey::from_wif("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D").unwrap();
    let pubkey = PublicKey::from_private_key(&secp, &privkey);

    let mut funding = Funding::initialize(pubkey, Network::Local).unwrap();

    let funding_tx_seen = bitcoin::Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: bitcoin::blockdata::transaction::OutPoint::null(),
            script_sig: bitcoin::blockdata::script::Script::default(),
            sequence: 0,
            witness: vec![],
        }],
        output: vec![TxOut {
            value: 100000,
            script_pubkey: bitcoin::blockdata::script::Script::default(),
        }],
    };

    funding.update(funding_tx_seen.clone()).unwrap();

    let _funding_datum = dbg!(datum::Transaction::<Bitcoin>::new_funding_seen(
        funding_tx_seen
    ));

    let datalock = DataLock {
        timelock: CSVTimelock::new(10),
        success: DoubleKeys::new(pubkey, pubkey),
        failure: DoubleKeys::new(pubkey, pubkey),
    };

    let fee = FeeStrategy::Fixed(SatPerVByte::from_sat(1));
    let politic = FeePolitic::Aggressive;

    let lock = Tx::<Lock>::initialize(&funding, datalock.clone(), &fee, politic).unwrap();

    let tx = lock.to_partial();

    let transaction_datum = dbg!(datum::Transaction::<Bitcoin>::new_lock(tx));

    dbg!(serialize_hex(&transaction_datum));
    let bytes = dbg!(serialize(&transaction_datum));
    let transaction_datum_2: datum::Transaction<Bitcoin> = dbg!(deserialize(&bytes).unwrap());

    assert_eq!(transaction_datum.tx_id(), transaction_datum_2.tx_id());
    assert_eq!(
        transaction_datum
            .tx()
            .try_into_partial_transaction()
            .unwrap(),
        transaction_datum_2
            .tx()
            .try_into_partial_transaction()
            .unwrap()
    );

    //assert!(false);
}
