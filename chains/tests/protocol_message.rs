use bitcoin::blockdata::transaction::Transaction;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::Signature;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::PartiallySignedTransaction;

use farcaster_core::protocol_message::{Abort, BuyProcedureSignature};

use farcaster_chains::bitcoin::{Bitcoin, ECDSAAdaptorSig, PDLEQ};

#[test]
fn create_abort_message() {
    let _ = Abort {
        error_body: Some(String::from("An error occured ;)")),
    };
}

#[test]
fn create_buy_procedure_signature_message() {
    let secp = Secp256k1::new();

    let ecdsa_sig = "3045022100b75f569de3e57f4f445bcf9e42be9e5b5128f317ab86e451fdfe7be5ffd6a7da0220776b30307b5d761512635dc0394573be7fe17b5300b160340dae370b641bc4ca";

    let tx = Transaction {
        version: 2,
        lock_time: 0,
        input: Vec::new(),
        output: Vec::new(),
    };

    let sig = Signature::from_der(&hex::decode(ecdsa_sig).expect("HEX decode should work here"))
        .expect("Parse DER should work here");

    let privkey: PrivateKey =
        PrivateKey::from_wif("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D").unwrap();
    let point = PublicKey::from_private_key(&secp, &privkey);

    let pdleq = PDLEQ;

    let _ = BuyProcedureSignature::<Bitcoin> {
        buy: (PartiallySignedTransaction::from_unsigned_tx(tx).expect("PSBT should work here")),
        buy_adaptor_sig: ECDSAAdaptorSig {
            sig,
            point,
            dleq: pdleq,
        },
    };
}
