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

//! Implementation of a Taproot strategy with on-chain scripts for the arbitrating blockchain
//! as Bitcoin. Inner implementation of [`BitcoinTaproot`].

use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

use crate::bitcoin::{Bitcoin, BitcoinTaproot, Btc, Strategy};
use crate::consensus::{self, CanonicalBytes};
use crate::crypto::{DeriveKeys, SharedKeyId};
//use crate::role::Arbitrating;

use bitcoin::secp256k1::{schnorr::Signature, KeyPair, XOnlyPublicKey};

/// Inner type for the Taproot strategy with on-chain scripts.
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct Taproot;

impl Strategy for Taproot {}

impl fmt::Display for Bitcoin<Taproot> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Bitcoin<Taproot>")
    }
}

impl FromStr for Bitcoin<Taproot> {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Taproot" | "taproot" => Ok(Self::new()),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl From<BitcoinTaproot> for Btc {
    fn from(v: BitcoinTaproot) -> Self {
        Self::Taproot(v)
    }
}

//impl Arbitrating for Bitcoin<Taproot> {}

impl TryFrom<Btc> for Bitcoin<Taproot> {
    type Error = consensus::Error;

    fn try_from(v: Btc) -> Result<Self, consensus::Error> {
        match v {
            Btc::Taproot(v) => Ok(v),
            _ => Err(consensus::Error::TypeMismatch),
        }
    }
}

impl DeriveKeys for Bitcoin<Taproot> {
    type PublicKey = XOnlyPublicKey;
    type PrivateKey = KeyPair;

    fn extra_public_keys() -> Vec<u16> {
        // No extra key
        vec![]
    }

    fn extra_shared_private_keys() -> Vec<SharedKeyId> {
        // No shared key in Bitcoin, transparent ledger
        vec![]
    }
}

impl CanonicalBytes for XOnlyPublicKey {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        self.serialize().as_ref().into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        XOnlyPublicKey::from_slice(bytes).map_err(consensus::Error::new)
    }
}

//impl Signatures for Bitcoin<Taproot> {
//    type Message = Sha256dHash;
//    type Signature = Signature;
//    type EncryptedSignature = Signature;
//}

impl CanonicalBytes for Signature {
    fn as_canonical_bytes(&self) -> Vec<u8> {
        (*self.as_ref()).into()
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, consensus::Error>
    where
        Self: Sized,
    {
        Signature::from_slice(bytes).map_err(consensus::Error::new)
    }
}
