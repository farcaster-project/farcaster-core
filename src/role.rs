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

//! Roles used to distinguish participants and blockchains during negotiation and swap phases.
//! Defines the trading roles and swap roles distributed among participants and blockchain roles
//! implemented on Bitcoin, Monero, etc.

use std::fmt::Debug;
use std::io;
use std::str::FromStr;

use crate::blockchain::Network;
use crate::consensus::{self, Decodable, Encodable};
use crate::crypto::{self, AccordantKeySet};

/// Possible roles during the negotiation phase. Any negotiation role can transition into any swap
/// role when negotiation is completed, the transition is described in the public offer.
#[derive(Display, Debug, Clone, Hash, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[display(Debug)]
pub enum TradeRole {
    /// The maker role create the public offer during the negotiation phase and waits for incoming
    /// connections.
    Maker,
    /// The taker role parses public offers and choose to connect to a maker node to start
    /// swapping.
    Taker,
}

impl TradeRole {
    /// Return the other role possible in the negotiation phase.
    pub fn other(&self) -> Self {
        match self {
            Self::Maker => Self::Taker,
            Self::Taker => Self::Maker,
        }
    }
}

impl Encodable for TradeRole {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            TradeRole::Maker => 0x01u8.consensus_encode(writer),
            TradeRole::Taker => 0x02u8.consensus_encode(writer),
        }
    }
}

impl Decodable for TradeRole {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u8 => Ok(TradeRole::Maker),
            0x02u8 => Ok(TradeRole::Taker),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl_strict_encoding!(TradeRole);

impl FromStr for TradeRole {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Maker" | "maker" => Ok(TradeRole::Maker),
            "Taker" | "taker" => Ok(TradeRole::Taker),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

/// Possible roles during the swap phase. When negotitation phase is completed [`TradeRole`] will
/// transition into swap role according to the [`PublicOffer`].
///
/// [`PublicOffer`]: crate::negotiation::PublicOffer
#[derive(Display, Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[display(Debug)]
pub enum SwapRole {
    /// Alice, the swap role, is the role starting with accordant blockchain assets and exchange
    /// them for arbitrating blockchain assets.
    Alice,
    /// Bob, the swap role, is the role starting with arbitrating blockchain assets and exchange
    /// them for accordant blockchain assets.
    Bob,
}

impl SwapRole {
    /// Return the other role possible in the swap phase.
    pub fn other(&self) -> Self {
        match self {
            Self::Alice => Self::Bob,
            Self::Bob => Self::Alice,
        }
    }
}

impl Encodable for SwapRole {
    fn consensus_encode<W: io::Write>(&self, writer: &mut W) -> Result<usize, io::Error> {
        match self {
            SwapRole::Alice => 0x01u8.consensus_encode(writer),
            SwapRole::Bob => 0x02u8.consensus_encode(writer),
        }
    }
}

impl Decodable for SwapRole {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u8 => Ok(SwapRole::Alice),
            0x02u8 => Ok(SwapRole::Bob),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl_strict_encoding!(SwapRole);

impl FromStr for SwapRole {
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Alice" | "alice" => Ok(SwapRole::Alice),
            "Bob" | "bob" => Ok(SwapRole::Bob),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

/// An accordant is the blockchain which does not need transaction inside the protocol nor
/// timelocks: it is the blockchain with fewer requirements for an atomic swap.
pub trait Accordant<Pk, Sk, Addr> {
    //: Asset + Address + Clone + Eq + Display + Debug
    /// Derive the lock address for the accordant blockchain.
    fn derive_lock_address(
        network: Network,
        keys: AccordantKeySet<Pk, Sk>,
    ) -> Result<Addr, crypto::Error>;
}
