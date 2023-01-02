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

//! A set of re-export messages with concrete types for Bitcoin and Monero swaps.

use crate::crypto::dleq::DLEQProof;
use crate::crypto::KeccakCommitment;
use crate::protocol::message;

use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::util::psbt::PartiallySignedTransaction;
use bitcoin::Address;
use ecdsa_fun::adaptor::EncryptedSignature;

pub type BuyProcedureSignature =
    message::BuyProcedureSignature<PartiallySignedTransaction, EncryptedSignature>;

pub type CommitAliceParameters = message::CommitAliceParameters<KeccakCommitment>;
pub type CommitBobParameters = message::CommitBobParameters<KeccakCommitment>;

pub type CoreArbitratingSetup =
    message::CoreArbitratingSetup<PartiallySignedTransaction, Signature>;

pub type RefundProcedureSignatures =
    message::RefundProcedureSignatures<Signature, EncryptedSignature>;

pub type RevealAliceParameters = message::RevealAliceParameters<
    PublicKey,
    monero::PublicKey,
    SecretKey,
    monero::PrivateKey,
    Address,
    DLEQProof,
>;
pub type RevealBobParameters = message::RevealBobParameters<
    PublicKey,
    monero::PublicKey,
    SecretKey,
    monero::PrivateKey,
    Address,
    DLEQProof,
>;
