use bitcoin::blockdata::transaction::Transaction;
use bitcoin::secp256k1::Signature;
use bitcoin::util::psbt::PartiallySignedTransaction;

use farcaster_core::chain::pairs::btcxmr::BtcXmr;
use farcaster_core::protocol_message::{Abort, BuyProcedureSignature};
use farcaster_core::swap::SwapId;

#[test]
fn create_abort_message() {
    let _ = Abort {
        swap_id: SwapId::random(),
        error_body: Some(String::from("An error occured ;)")),
    };
}

#[test]
fn create_buy_procedure_signature_message() {
    let ecdsa_sig = "3045022100b75f569de3e57f4f445bcf9e42be9e5b5128f317ab86e451fdfe7be5ffd6a7da0220776b30307b5d761512635dc0394573be7fe17b5300b160340dae370b641bc4ca";

    let tx = Transaction {
        version: 2,
        lock_time: 0,
        input: Vec::new(),
        output: Vec::new(),
    };

    let buy_adaptor_sig =
        Signature::from_der(&hex::decode(ecdsa_sig).expect("HEX decode should work here"))
            .expect("Parse DER should work here");

    let _ = BuyProcedureSignature::<BtcXmr> {
        swap_id: SwapId::random(),
        buy: (PartiallySignedTransaction::from_unsigned_tx(tx).expect("PSBT should work here")),
        buy_adaptor_sig,
    };
}
