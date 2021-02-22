//! Protocol messages exchanged between swap daemons

use secp256k1::Secp256k1;
use secp256k1::key::PublicKey;
use bitcoin::hash_types::PubkeyHash;
use std::convert::TryFrom;

use crate::roles::{Alice, Bob};
//use crate::session::Session;

pub trait ProtocolMessage {}

pub struct CommitAliceSessionParams {
    pub buy: PubkeyHash,
    pub cancel: PubkeyHash,
    pub refund: PubkeyHash,
    pub punish: PubkeyHash,
    pub adaptor: PubkeyHash,
    pub spend: String,
    pub view: String,
}

//impl TryFrom<Session<Alice>> for CommitAliceSessionParams {
//    type Error = &'static str;
//
//    /// Derive the commitment message from a session
//    fn try_from(value: Session<Alice>) -> Result<Self, Self::Error> {
//        let secp = Secp256k1::new();
//
//        Ok(CommitAliceSessionParams {
//            buy: PublicKey::from_secret_key(&secp, &value.get_params().buy),
//            cancel: value.get_params().cancel.clone(),
//            refund: value.get_params().refund.clone(),
//            punish: value.get_params().punish.clone(),
//            adaptor: value.get_params().spend.clone(),
//            spend: value.get_params().spend.clone(),
//            view: value.get_params().view.clone(),
//        })
//    }
//}

pub struct CommitBobSessionParams {
    pub buy: PubkeyHash,
    pub cancel: PubkeyHash,
    pub refund: PubkeyHash,
    pub adaptor: PubkeyHash,
    pub spend: String,
    pub view: String,
}

//impl TryFrom<Session<Bob>> for CommitBobSessionParams {
//    type Error = &'static str;
//
//    /// Derive the commitment message from a session
//    fn try_from(value: Session<Bob>) -> Result<Self, Self::Error> {
//        Ok(CommitBobSessionParams {
//            buy: value.get_params().buy.clone(),
//            cancel: value.get_params().cancel.clone(),
//            refund: value.get_params().refund.clone(),
//            adaptor: value.get_params().spend.clone(),
//            spend: value.get_params().spend.clone(),
//            view: value.get_params().view.clone(),
//        })
//    }
//}

pub struct RevealAliceSessionParams {
    pub buy: String,
    pub cancel: String,
    pub refund: String,
    pub punish: String,
    pub adaptor: String,
    pub address: String,
    pub spend: String,
    pub view: String,
    pub proof: String,
}

pub struct RevealBobSessionParams {
    pub buy: String,
    pub cancel: String,
    pub refund: String,
    pub adaptor: String,
    pub address: String,
    pub spend: String,
    pub view: String,
    pub proof: String,
}
