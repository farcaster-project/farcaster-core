#![cfg(feature = "rpc")]

use farcaster_core::blockchain::*;
use farcaster_core::chain::bitcoin::fee::SatPerVByte;
use farcaster_core::script::*;
use farcaster_core::transaction::*;

use farcaster_core::chain::bitcoin::transaction::*;
use farcaster_core::chain::bitcoin::*;

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

        let funding_tx_seen = fund_address!(address.as_ref());
        // Minimum of fee of 122 sat
        let target_amount = amount::Amount::from_sat(funding_tx_seen.output[0].value - 122);

        funding.update(funding_tx_seen).unwrap();

        let datalock = DataLock {
            timelock: timelock::CSVTimelock::new(10),
            success: DoubleKeys::new(pubkey_a1, pubkey_b1),
            failure: DoubleKeys::new(pubkey_a2, pubkey_b2),
        };

        let fee = FeeStrategy::Fixed(SatPerVByte::from_sat(1));
        let politic = FeePolitic::Aggressive;

        let mut lock = Tx::<Lock>::initialize(&funding, datalock.clone(), target_amount).unwrap();

        //
        // Create cancel tx
        //
        let datapunishablelock = DataPunishableLock {
            timelock: timelock::CSVTimelock::new(10),
            success: DoubleKeys::new(pubkey_a1, pubkey_b1),
            failure: pubkey_a2,
        };

        let mut cancel =
            Tx::<Cancel>::initialize(&lock, datalock, datapunishablelock.clone()).unwrap();

        // Set the fees according to the given strategy
        Bitcoin::set_fee(cancel.partial_mut(), &fee, politic).unwrap();

        //
        // Create refund tx
        //
        let (new_address, _, _) = new_address!();
        let mut refund =
            Tx::<Refund>::initialize(&cancel, datapunishablelock, new_address.into()).unwrap();

        // Set the fees according to the given strategy
        Bitcoin::set_fee(refund.partial_mut(), &fee, politic).unwrap();

        //
        // Co-Sign cancel
        //
        let msg = cancel
            .generate_witness_message(ScriptPath::Failure)
            .unwrap();
        let sig = sign_hash(msg, &secret_a2.key).unwrap();
        cancel.add_witness(pubkey_a2, sig).unwrap();
        let msg = cancel
            .generate_witness_message(ScriptPath::Failure)
            .unwrap();
        let sig = sign_hash(msg, &secret_b2.key).unwrap();
        cancel.add_witness(pubkey_b2, sig).unwrap();

        //
        // Finalize cancel
        //
        let cancel_finalized = cancel.finalize_and_extract().unwrap();

        //
        // Sign lock tx
        //
        let msg = lock.generate_witness_message(ScriptPath::Success).unwrap();
        let sig = sign_hash(msg, &secret_a1.key).unwrap();
        lock.add_witness(pubkey_a1, sig).unwrap();
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

        // Broadcast the lock, wait 1 block, and directly cancel without waiting the lock
        then broadcast lock_finalized;
        then mine 1;
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
