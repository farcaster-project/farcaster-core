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

//! Defines the high level of a swap between a Arbitrating blockchain and a Accordant blockchain
//! and its concrete instances of swaps.

use std::io;

use strict_encoding::{StrictDecode, StrictEncode};

use crate::consensus::{self, Decodable, Encodable};
use crate::trade::TradeId;
use crate::Uuid;

pub mod btcxmr;

/// The identifier of a swap. This is a wrapper around [`Uuid`] that can be constructed from
/// [`TradeId`].
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Display,
    Serialize,
    Deserialize,
    StrictEncode,
    StrictDecode,
)]
#[serde(transparent)]
#[display(inner)]
pub struct SwapId(pub Uuid);

impl From<Uuid> for SwapId {
    fn from(u: Uuid) -> Self {
        SwapId(u)
    }
}

impl From<uuid::Uuid> for SwapId {
    fn from(u: uuid::Uuid) -> Self {
        SwapId(u.into())
    }
}

impl From<TradeId> for SwapId {
    fn from(t: TradeId) -> Self {
        SwapId(t.0)
    }
}

impl Encodable for SwapId {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(s)
    }
}

impl Decodable for SwapId {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self(Decodable::consensus_decode(d)?))
    }
}
