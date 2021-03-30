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

#[test]
fn create_funding_generic() {
    let client = rpc::setup().unwrap();

    let (
        _secp,
        privkey_a,
        pubkey_a,
        _privkey_b,
        pubkey_b,
        privkey_a2,
        pubkey_a2,
        privkey_b2,
        pubkey_b2,
    ) = rpc::keys();

    let mut funding = Funding::initialize(pubkey_a, Network::Local).unwrap();
    let address = funding.get_address().unwrap();

    let blocks = gen_to_add!(address with client);

    let block_hash = blocks[0];
    let block = client.get_block(&block_hash).unwrap();
    let funding_tx_seen = block.coinbase().unwrap().clone();

    funding.update(funding_tx_seen).unwrap();

    let datalock = DataLock {
        timelock: CSVTimelock::new(10),
        success: DoubleKeys::new(pubkey_a, pubkey_b),
        failure: DoubleKeys::new(pubkey_a2, pubkey_b2),
    };

    let fee = FeeStrategy::Fixed(SatPerVByte::from_sat(50));
    let politic = FeePolitic::Aggressive;

    let mut lock = Tx::<Lock>::initialize(&funding, datalock.clone(), &fee, politic).unwrap();

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

    //
    // Create refund tx
    //
    let new_address = gen_new_add!();
    let _refund =
        Tx::<Refund>::initialize(&cancel, datapunishablelock, new_address, &fee, politic).unwrap();

    //
    // Co-Sign refund
    //
    let _sig = cancel.generate_failure_witness(&privkey_a2).unwrap();
    let _sig = cancel.generate_failure_witness(&privkey_b2).unwrap();

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

    gen_to_add!(100 => address with client);

    // Broadcast the lock
    send!(lock_finalized with client);
    // Mine the transaction
    gen_to_add!(10 => address with client);

    // Broadcast the cancel
    send!(cancel_finalized with client);
    // Mine the transaction
    gen_to_add!(address with client);

    assert!(true);
}
