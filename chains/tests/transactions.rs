#![cfg(feature = "rpc")]

use farcaster_chains::bitcoin::fee::SatPerVByte;
use farcaster_core::blockchain::*;
use farcaster_core::script::*;
use farcaster_core::transaction::*;

use farcaster_chains::bitcoin::transaction::*;
use farcaster_chains::bitcoin::*;

use bitcoincore_rpc::RpcApi;

#[macro_use]
mod rpc;

macro_rules! setup_txs {
    () => {{
        let (_, pubkey_a1, secret_a1) = new_address!();
        let (_, pubkey_a2, secret_a2) = new_address!();

        let (_, pubkey_b1, _secret_b1) = new_address!();
        let (_, pubkey_b2, secret_b2) = new_address!();

        let mut funding = Funding::initialize(pubkey_a1, Network::Local).unwrap();
        let address = funding.get_address().unwrap();

        let funding_tx_seen = fund_address!(address);

        funding.update(funding_tx_seen).unwrap();

        let datalock = DataLock {
            timelock: CSVTimelock::new(10),
            success: DoubleKeys::new(pubkey_a1, pubkey_b1),
            failure: DoubleKeys::new(pubkey_a2, pubkey_b2),
        };

        let fee = FeeStrategy::Fixed(SatPerVByte::from_sat(1));
        let politic = FeePolitic::Aggressive;

        let mut lock = Tx::<Lock>::initialize(&funding, datalock.clone(), &fee, politic).unwrap();

        //
        // Create cancel tx
        //
        let datapunishablelock = DataPunishableLock {
            timelock: CSVTimelock::new(10),
            success: DoubleKeys::new(pubkey_a1, pubkey_b1),
            failure: pubkey_a2,
        };

        let mut cancel =
            Tx::<Cancel>::initialize(&lock, datalock, datapunishablelock.clone(), &fee, politic)
                .unwrap();

        //
        // Create refund tx
        //
        let (new_address, _, _) = new_address!();
        let refund =
            Tx::<Refund>::initialize(&cancel, datapunishablelock, new_address, &fee, politic)
                .unwrap();

        //
        // Co-Sign refund
        //
        let _sig = cancel.generate_failure_witness(&secret_a2).unwrap();
        let _sig = cancel.generate_failure_witness(&secret_b2).unwrap();

        //
        // Finalize for failure path
        //
        let cancel_finalized = cancel.finalize_and_extract().unwrap();

        //
        // Sign lock tx
        //
        let _sig = lock.generate_witness(&secret_a1).unwrap();
        let lock_finalized = lock.finalize_and_extract().unwrap();

        (lock_finalized, cancel_finalized, refund)
    }};
}

#[test]
fn create_transactions() {
    setup_txs!();
}

#[test]
fn broadcast_lock() {
    let (lock_finalized, _, _) = setup_txs!();

    rpc! {
        // Wait 100 blocks to unlock the coinbase
        mine 100;

        // Broadcast the lock and mine the number of blocks needed for CSV
        then broadcast lock_finalized;
        then mine 1;
    }
}

#[test]
#[should_panic]
fn broadcast_cancel_before_timelock() {
    let (lock_finalized, cancel_finalized, _) = setup_txs!();

    rpc! {
        // Wait 100 blocks to unlock the coinbase
        mine 100;

        // Broadcast the lock and directly cancel without waiting the lock
        then broadcast lock_finalized;
        then broadcast cancel_finalized;
    }
}

#[test]
fn broadcast_cancel_after_timelock() {
    let (lock_finalized, cancel_finalized, _) = setup_txs!();

    rpc! {
        // Wait 100 blocks to unlock the coinbase
        mine 100;

        // Broadcast the lock and mine the number of blocks needed for CSV
        then broadcast lock_finalized;
        then mine 10;

        // Broadcast the cancel and mine the transaction
        then broadcast cancel_finalized;
        then mine 1;
    }
}
