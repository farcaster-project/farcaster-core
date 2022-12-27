// Copyright 2021-2022 Farcaster Devs
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

#![cfg(feature = "rpc")]

use farcaster_core::bitcoin::fee::SatPerKvB;
use farcaster_core::blockchain::*;
use farcaster_core::script::*;
use farcaster_core::transaction::*;

use farcaster_core::bitcoin::segwitv0::*;
use farcaster_core::bitcoin::*;

use bitcoin::Amount;
use bitcoincore_rpc::RpcApi;

#[macro_use]
mod rpc;

macro_rules! setup_txs {
    () => {{
        let (_, pubkey_a1, secret_a1) = new_address!();
        //let (_, pubkey_a2, secret_a2) = new_address!();

        let (_, pubkey_b1, secret_b1) = new_address!();
        //let (_, pubkey_b2, secret_b2) = new_address!();

        let mut funding = FundingTx::initialize(pubkey_a1, Network::Local).unwrap();

        //
        // Create a wallet, mined funds, send to funding address with multiple UTXOs
        //
        if let Err(_) = rpc::CLIENT.create_wallet("test_wallet", Some(false), None, None, None) {
            let wallets = rpc::CLIENT.list_wallets().unwrap();
            if wallets.len() == 0 {
                rpc::CLIENT.load_wallet("test_wallet").unwrap();
            }
            if wallets.len() > 1 {
                panic!("More than one wallet loaded!");
            }
        }

        let wallet_address = rpc::CLIENT.get_new_address(None, None).unwrap();
        rpc::CLIENT.generate_to_address(4, &wallet_address).unwrap();
        mine!(100);
        let target_swap_amount = bitcoin::Amount::from_btc(8.0).unwrap();

        let address = funding.get_address().unwrap();
        let txid = rpc::CLIENT
            .send_to_address(
                &address,
                target_swap_amount,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let funding_tx_seen: bitcoin::Transaction = rpc::CLIENT.get_by_id(&txid).unwrap();
        // Minimum of fee of 122 sat
        let target_amount = Amount::from_sat(target_swap_amount.as_sat() - 122);
        funding.update(funding_tx_seen).unwrap();

        let datalock = DataLock {
            timelock: timelock::CSVTimelock::new(10),
            success: DoubleKeys::new(pubkey_a1, pubkey_b1),
            failure: DoubleKeys::new(pubkey_a1, pubkey_b1),
        };

        let fee = FeeStrategy::Fixed(SatPerKvB::from_sat(1));
        let politic = FeePriority::Low;

        let mut lock = LockTx::initialize(&funding, datalock.clone(), target_amount).unwrap();

        //
        // Create cancel tx
        //
        let datapunishablelock = DataPunishableLock {
            timelock: timelock::CSVTimelock::new(10),
            success: DoubleKeys::new(pubkey_a1, pubkey_b1),
            failure: pubkey_a1,
        };

        let mut cancel =
            CancelTx::initialize(&lock, datalock.clone(), datapunishablelock.clone()).unwrap();

        // Set the fees according to the given strategy
        cancel.as_partial_mut().set_fee(&fee, politic).unwrap();

        //
        // Create refund tx
        //
        let (new_address, _, _) = new_address!();
        let mut refund = RefundTx::initialize(&cancel, new_address.clone()).unwrap();

        // Set the fees according to the given strategy
        refund.as_partial_mut().set_fee(&fee, politic).unwrap();

        lock.verify_template(datalock.clone()).unwrap();
        cancel
            .verify_template(datalock.clone(), datapunishablelock.clone())
            .unwrap();
        refund.verify_template(new_address.clone()).unwrap();

        //
        // Co-Sign refund
        //
        let msg = refund
            .generate_witness_message(ScriptPath::Success)
            .unwrap();
        let sig = sign_hash(msg, &secret_a1).unwrap();
        refund.add_witness(pubkey_a1, sig).unwrap();
        let msg = refund
            .generate_witness_message(ScriptPath::Success)
            .unwrap();
        let sig = sign_hash(msg, &secret_b1).unwrap();
        refund.add_witness(pubkey_b1, sig).unwrap();

        //
        // Finalize refund
        //
        let refund_finalized =
            Broadcastable::<bitcoin::Transaction>::finalize_and_extract(&mut refund).unwrap();

        //
        // Co-Sign cancel
        //
        let msg = cancel
            .generate_witness_message(ScriptPath::Failure)
            .unwrap();
        let sig = sign_hash(msg, &secret_a1).unwrap();
        cancel.add_witness(pubkey_a1, sig).unwrap();
        let msg = cancel
            .generate_witness_message(ScriptPath::Failure)
            .unwrap();
        let sig = sign_hash(msg, &secret_b1).unwrap();
        cancel.add_witness(pubkey_b1, sig).unwrap();

        //
        // Finalize cancel
        //
        let cancel_finalized =
            Broadcastable::<bitcoin::Transaction>::finalize_and_extract(&mut cancel).unwrap();

        //
        // Create buy tx
        //
        let (new_address, _, _) = new_address!();
        let mut buy = BuyTx::initialize(&lock, datalock.clone(), new_address.clone()).unwrap();

        // Set the fees according to the given strategy
        buy.as_partial_mut().set_fee(&fee, politic).unwrap();

        buy.verify_template(new_address.clone()).unwrap();

        //
        // Co-Sign buy
        //
        let msg = buy.generate_witness_message(ScriptPath::Success).unwrap();
        let sig = sign_hash(msg, &secret_a1).unwrap();
        buy.add_witness(pubkey_a1, sig).unwrap();
        let msg = buy.generate_witness_message(ScriptPath::Success).unwrap();
        let sig = sign_hash(msg, &secret_b1).unwrap();
        buy.add_witness(pubkey_b1, sig).unwrap();

        //
        // Finalize buy
        //
        let buy_finalized =
            Broadcastable::<bitcoin::Transaction>::finalize_and_extract(&mut buy).unwrap();

        //
        // Sign lock tx
        //
        let msg = lock.generate_witness_message(ScriptPath::Success).unwrap();
        let sig = sign_hash(msg, &secret_a1).unwrap();
        lock.add_witness(pubkey_a1, sig).unwrap();
        let lock_finalized =
            Broadcastable::<bitcoin::Transaction>::finalize_and_extract(&mut lock).unwrap();

        //
        // Create punish tx
        //
        let (new_address, _, _) = new_address!();
        let mut punish =
            PunishTx::initialize(&cancel, datapunishablelock, new_address.into()).unwrap();

        // Set the fees according to the given strategy
        punish.as_partial_mut().set_fee(&fee, politic).unwrap();

        //
        // Sign punish
        //
        let msg = punish
            .generate_witness_message(ScriptPath::Failure)
            .unwrap();
        let sig = sign_hash(msg, &secret_a1).unwrap();
        punish.add_witness(pubkey_a1, sig).unwrap();

        //
        // Finalize buy
        //
        let punish_finalized =
            Broadcastable::<bitcoin::Transaction>::finalize_and_extract(&mut punish).unwrap();

        (
            lock_finalized,
            cancel_finalized,
            refund_finalized,
            buy_finalized,
            punish_finalized,
        )
    }};
}

#[test]
fn create_transactions() {
    setup_txs!();
}

#[test]
fn broadcast_lock() {
    let (lock, _, _, _, _) = setup_txs!();

    rpc! {
        // Wait 100 blocks to unlock the coinbase
        mine 100;

        // Broadcast the lock and mine the transaction
        then broadcast lock;
        then mine 1;
    }
}

#[test]
fn broadcast_lock_and_buy() {
    let (lock, _, _, buy, _) = setup_txs!();

    rpc! {
        // Wait 100 blocks to unlock the coinbase
        mine 100;

        // Broadcast the lock, mine 1 block, and broadcast buy
        then broadcast lock;
        then mine 1;
        then broadcast buy;
    }
}

#[test]
#[should_panic]
fn broadcast_cancel_before_timelock() {
    let (lock, cancel, _, _, _) = setup_txs!();

    rpc! {
        // Wait 100 blocks to unlock the coinbase
        mine 100;

        // Broadcast the lock, wait 1 block, and directly cancel without waiting the lock
        then broadcast lock;
        then mine 1;
        then broadcast cancel;
    }
}

#[test]
fn broadcast_cancel_after_timelock() {
    let (lock, cancel, _, _, _) = setup_txs!();

    rpc! {
        // Wait 100 blocks to unlock the coinbase
        mine 100;

        // Broadcast the lock and mine the number of blocks needed for CSV
        then broadcast lock;
        then mine 10;

        // Broadcast the cancel and mine the transaction
        then broadcast cancel;
        then mine 1;
    }
}

#[test]
fn full_refund_path() {
    let (lock, cancel, refund, _, _) = setup_txs!();

    rpc! {
        // Wait 100 blocks to unlock the coinbase
        mine 100;

        // Broadcast the lock and mine the number of blocks needed for CSV
        then broadcast lock;
        then mine 10;

        // Broadcast the cancel and mine the transaction
        then broadcast cancel;
        then mine 1;
        then broadcast refund;
        then mine 1;
    }
}

#[test]
#[should_panic]
fn broadcast_punish_before_timelock() {
    let (lock, cancel, _, _, punish) = setup_txs!();

    rpc! {
        // Wait 100 blocks to unlock the coinbase
        mine 100;

        // Broadcast the lock and mine the number of blocks needed for CSV
        then broadcast lock;
        then mine 10;

        // Broadcast the cancel, wait 1 block, and directly punish without waiting the lock
        then broadcast cancel;
        then mine 1;
        // This should panic
        then broadcast punish;
    }
}

#[test]
fn broadcast_punish_after_timelock() {
    let (lock, cancel, _, _, punish) = setup_txs!();

    rpc! {
        // Wait 100 blocks to unlock the coinbase
        mine 100;

        // Broadcast the lock and mine the number of blocks needed for CSV
        then broadcast lock;
        then mine 10;

        // Broadcast the cancel and mine the number of blocks needed for CSV
        then broadcast cancel;
        then mine 10;

        // Punish after the timelock
        then broadcast punish;
    }
}
