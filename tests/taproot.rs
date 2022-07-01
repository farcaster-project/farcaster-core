#![cfg(all(feature = "rpc", feature = "taproot"))]

use farcaster_core::bitcoin::fee::SatPerVByte;
use farcaster_core::bitcoin::taproot::*;
use farcaster_core::bitcoin::*;
use farcaster_core::blockchain::*;
use farcaster_core::script::*;
use farcaster_core::transaction::*;

use bitcoin::secp256k1::Secp256k1;
use bitcoin::Amount;
use bitcoincore_rpc::json::AddressType;
use bitcoincore_rpc::RpcApi;

#[macro_use]
mod rpc;

#[test]
fn taproot_funding_tx() {
    let (_, xpubkey_a1, keypair_a1) = new_address!(taproot);
    //let (_, pubkey_a2, secret_a2) = new_address!();

    let (_, xpubkey_b1, keypair_b1) = new_address!(taproot);
    //let (_, pubkey_b2, secret_b2) = new_address!();

    let mut funding = FundingTx::initialize(xpubkey_a1, Network::Local).unwrap();

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

    let wallet_address = rpc::CLIENT
        .get_new_address(None, Some(AddressType::Bech32))
        .unwrap();
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
        success: DoubleKeys::new(&xpubkey_a1, &xpubkey_b1),
        failure: DoubleKeys::new(&xpubkey_a1, &xpubkey_b1),
    };

    let fee = FeeStrategy::Fixed(SatPerVByte::from_sat(1));
    let politic = FeePriority::Low;

    let mut lock = LockTx::initialize(&funding, datalock.clone(), target_amount).unwrap();

    //
    // Sign lock tx
    //
    let msg = Witnessable::<BitcoinTaproot>::generate_witness_message(&lock, ScriptPath::Success)
        .unwrap();
    // tweak key pair with tap_tweak funding
    let secp = Secp256k1::new();
    let tweak = bitcoin::util::taproot::TaprootSpendInfo::new_key_spend(&secp, xpubkey_a1, None)
        .tap_tweak();
    let mut tweaked_keypair = keypair_a1.clone();
    tweaked_keypair.tweak_add_assign(&secp, &tweak).unwrap();
    let sig = sign_hash(msg, &tweaked_keypair).unwrap();
    Witnessable::<BitcoinTaproot>::add_witness(&mut lock, xpubkey_a1, sig).unwrap();
    let lock_finalized = Broadcastable::<BitcoinTaproot>::finalize_and_extract(&mut lock).unwrap();

    rpc! {
        // Wait 100 blocks to unlock the coinbase
        mine 100;

        // Broadcast the lock and mine the transaction
        then broadcast lock_finalized;
        then mine 1;
    }
}
