#![cfg(all(feature = "rpc", feature = "taproot"))]

use farcaster_core::bitcoin::taproot::*;
use farcaster_core::blockchain::*;
use farcaster_core::transaction::*;

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
    println!("{:?}", address);
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
}
