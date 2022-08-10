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

//! Negotiation helpers and structures. Buyer and seller helpers to create offer and public offers
//! allowing agreement on assets, quantities and parameters of a swap among maker and taker.
//!
//! ## Public Offer
//!
//! A public offer is shared across the network by a maker. It contains all the data regarding what
//! the trade is about (assets, amounts, timings, etc.).
//!
//! A public offer is formatted like (base58 is Monero base58):
//!
//! ```text
//! "Offer:" | base58(serialize(public_offer))
//! ```
//!
//! The public offer contains:
//!
//! - A version number, used for the version and potentially enabling features
//! - The offer, containing the asset types, amounts, timings, etc.
//! - A node identifier, used to secure the communication with the other peer
//! - A peer address, used to connect to the other peer

use bitcoin::secp256k1::PublicKey;
use inet2_addr::InetSocketAddr;
use serde::ser::{Serialize, Serializer};
use serde::{de, Deserialize, Deserializer};
use std::fmt::Display;
use std::str::FromStr;
use thiserror::Error;
use tiny_keccak::{Hasher, Keccak};
use uuid::Uuid;

use std::fmt;
use std::io;

use crate::blockchain::{Blockchain, FeeStrategy, Network};
use crate::consensus::{self, serialize, serialize_hex, CanonicalBytes, Decodable, Encodable};
use crate::hash::HashString;
use crate::protocol::ArbitratingParameters;
use crate::role::{SwapRole, TradeRole};

/// First six magic bytes of a public offer. Bytes are included inside the base58 encoded part.
pub const OFFER_MAGIC_BYTES: &[u8; 6] = b"FCSWAP";

/// Prefix for serialized public offer.
pub const PUB_OFFER_PREFIX: &str = "Offer:";

/// A public offer version containing the version and the activated features if any.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display, Serialize, Deserialize)]
#[display("v{0}")]
pub struct Version(u16);

impl Version {
    /// Create a new version 1 public offer.
    pub fn new_v1() -> Self {
        Self::new(1)
    }

    /// Create a public offer from a raw version and feature `u16`.
    pub fn new(version: u16) -> Self {
        Version(version)
    }

    /// Version and features as `u16`.
    pub fn to_u16(&self) -> u16 {
        self.0
    }
}

impl Encodable for Version {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        self.to_u16().consensus_encode(s)
    }
}

impl Decodable for Version {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self::new(Decodable::consensus_decode(d)?))
    }
}

/// Negotiation errors used when manipulating offers, public offers and its version.
#[derive(Error, Debug)]
pub enum Error {
    /// The public offer version is not supported.
    #[error("Unsupported version")]
    UnsupportedVersion,
    /// The public offer signature does not pass the validation tests.
    #[error("Invalid signature")]
    InvalidSignature,
}

fixed_hash::construct_fixed_hash!(
    /// Identify an offer by it's content, internally store the hash of the offer serialized with
    /// Farcaster consensus.
    pub struct OfferFingerprint(32);
);

impl Serialize for OfferFingerprint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(format!("{:#x}", self).as_ref())
    }
}

impl<'de> Deserialize<'de> for OfferFingerprint {
    fn deserialize<D>(deserializer: D) -> Result<OfferFingerprint, D::Error>
    where
        D: Deserializer<'de>,
    {
        OfferFingerprint::from_str(&deserializer.deserialize_string(HashString)?)
            .map_err(de::Error::custom)
    }
}

/// An offer is created by a [`TradeRole::Maker`] before the start of his daemon, it references all
/// the data needed to parametrize a trade and be validated from a [`TradeRole::Taker`]
/// perspective. The daemon start when the maker is ready to finalize his offer, transforming the
/// offer into a [`PublicOffer`] which contains the data needed to a taker to connect to the
/// maker's daemon.
///
/// ## Serde implementation
/// Amount types may have multiple serialization representation, e.g. btc and sat for bitcoin or
/// xmr and pico for monero. Using [`Display`] and [`FromStr`] unifies the interface to
/// de/serialize generic amounts.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Offer<Amt, Bmt, Ti, F> {
    /// The offer unique identifier.
    pub uuid: Uuid,
    /// Type of offer and network to use.
    pub network: Network,
    /// The chosen arbitrating blockchain.
    pub arbitrating_blockchain: Blockchain,
    /// The chosen accordant blockchain.
    pub accordant_blockchain: Blockchain,
    /// Amount of arbitrating assets to exchanged.
    #[serde(with = "string")]
    #[serde(bound(serialize = "Amt: Display"))]
    #[serde(bound(deserialize = "Amt: FromStr, Amt::Err: Display"))]
    pub arbitrating_amount: Amt,
    /// Amount of accordant assets to exchanged.
    #[serde(with = "string")]
    #[serde(bound(serialize = "Bmt: Display"))]
    #[serde(bound(deserialize = "Bmt: FromStr, Bmt::Err: Display"))]
    pub accordant_amount: Bmt,
    /// The cancel timelock parameter of the arbitrating blockchain.
    pub cancel_timelock: Ti,
    /// The punish timelock parameter of the arbitrating blockchain.
    pub punish_timelock: Ti,
    /// The chosen fee strategy for the arbitrating transactions.
    pub fee_strategy: FeeStrategy<F>,
    /// The future maker swap role.
    pub maker_role: SwapRole,
}

mod string {
    use std::fmt::Display;
    use std::str::FromStr;

    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Display,
        S: Serializer,
    {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr,
        T::Err: Display,
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

impl<Amt, Bmt, Ti, F> Display for Offer<Amt, Bmt, Ti, F>
where
    Self: Encodable,
    Amt: Display,
    Bmt: Display,
    Ti: Display,
    F: Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Uuid: {}", self.uuid)?;
        writeln!(f, "Fingerprint: {:?}", self.fingerprint())?;
        writeln!(f, "Network: {}", self.network)?;
        writeln!(f, "Blockchain: {}", self.arbitrating_blockchain)?;
        writeln!(f, "- amount: {}", self.arbitrating_amount)?;
        writeln!(f, "Blockchain: {}", self.accordant_blockchain)?;
        writeln!(f, "- amount: {}", self.accordant_amount)?;
        writeln!(f, "Timelocks")?;
        writeln!(f, "- cancel: {}", self.cancel_timelock)?;
        writeln!(f, "- punish: {}", self.punish_timelock)?;
        writeln!(f, "Fee strategy: {}", self.fee_strategy)?;
        writeln!(f, "Maker swap role: {}", self.maker_role)
    }
}

impl<Amt, Bmt, Ti, F> Offer<Amt, Bmt, Ti, F> {
    /// Transform the offer in a public offer of [`Version`] 1.
    pub fn to_public_v1(
        self,
        node_id: PublicKey,
        peer_address: InetSocketAddr,
    ) -> PublicOffer<Amt, Bmt, Ti, F> {
        PublicOffer {
            version: Version::new_v1(),
            offer: self,
            node_id,
            peer_address,
        }
    }

    /// Return the future swap role for the given trade role.
    pub fn swap_role(&self, trade_role: &TradeRole) -> SwapRole {
        match trade_role {
            TradeRole::Maker => self.maker_role,
            TradeRole::Taker => self.maker_role.other(),
        }
    }
}

impl<Amt, Bmt, Ti, F> Offer<Amt, Bmt, Ti, F> {
    /// Return the unique offer identifier. Same as [`Self::uuid()`].
    pub fn id(&self) -> Uuid {
        self.uuid()
    }

    /// Return the unique offer identifier.
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    /// Reset offer's uuid with a new identifier.
    pub fn randomize_uuid(&mut self) {
        self.uuid = Uuid::new_v4();
    }
}

impl<Amt, Bmt, Ti, F> Offer<Amt, Bmt, Ti, F>
where
    Self: Encodable,
{
    /// Generate the [`OfferFingerprint`] from the offer. The fingerprint identifies the content of
    /// an offer (**without the uuid**) by taking the hash value of its serialization.
    pub fn fingerprint(&self) -> OfferFingerprint {
        let mut keccak = Keccak::v256();
        let mut out = [0u8; 32];
        keccak.update(&serialize(self)[16..]);
        keccak.finalize(&mut out);
        OfferFingerprint(out)
    }
}

impl<Amt, Bmt, Ti, F> Encodable for Offer<Amt, Bmt, Ti, F>
where
    Amt: CanonicalBytes,
    Bmt: CanonicalBytes,
    Ti: CanonicalBytes,
    F: CanonicalBytes,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.uuid.to_bytes_le().consensus_encode(s)?;
        len += self.network.consensus_encode(s)?;
        len += self.arbitrating_blockchain.consensus_encode(s)?;
        len += self.accordant_blockchain.consensus_encode(s)?;
        len += self
            .arbitrating_amount
            .as_canonical_bytes()
            .consensus_encode(s)?;
        len += self
            .accordant_amount
            .as_canonical_bytes()
            .consensus_encode(s)?;
        len += self
            .cancel_timelock
            .as_canonical_bytes()
            .consensus_encode(s)?;
        len += self
            .punish_timelock
            .as_canonical_bytes()
            .consensus_encode(s)?;
        len += self.fee_strategy.consensus_encode(s)?;
        Ok(len + self.maker_role.consensus_encode(s)?)
    }
}

impl<Amt, Bmt, Ti, F> Decodable for Offer<Amt, Bmt, Ti, F>
where
    Amt: CanonicalBytes,
    Bmt: CanonicalBytes,
    Ti: CanonicalBytes,
    F: CanonicalBytes,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Offer {
            uuid: Uuid::from_bytes_le(Decodable::consensus_decode(d)?),
            network: Decodable::consensus_decode(d)?,
            arbitrating_blockchain: Decodable::consensus_decode(d)?,
            accordant_blockchain: Decodable::consensus_decode(d)?,
            arbitrating_amount: Amt::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            accordant_amount: Bmt::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            cancel_timelock: Ti::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            punish_timelock: Ti::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            fee_strategy: Decodable::consensus_decode(d)?,
            maker_role: Decodable::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(Offer<Amt, Bmt, Ti, F>, Amt: CanonicalBytes, Bmt: CanonicalBytes, Ti: CanonicalBytes, F: CanonicalBytes,);

/// A public offer is shared across [`TradeRole::Maker`]'s prefered network to signal is willing of
/// trading some assets at some conditions. The assets and condition are defined in the [`Offer`],
/// maker peer connection information are contained in the public offer.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct PublicOffer<Amt, Bmt, Ti, F> {
    /// The public offer version.
    pub version: Version,
    /// The content of the offer.
    #[serde(bound(serialize = "Amt: Display, Bmt: Display, Ti: Serialize, F: Serialize"))]
    #[serde(bound(
        deserialize = "Amt: FromStr, Amt::Err: Display, Bmt: FromStr, Bmt::Err: Display, Ti: Deserialize<'de>, F: Deserialize<'de>"
    ))]
    pub offer: Offer<Amt, Bmt, Ti, F>,
    /// Node public key, used both as an ID and encryption key for per-session ECDH.
    pub node_id: PublicKey,
    /// Address of the listening daemon's peer. An internet socket address, which consists of an IP
    /// or Tor address and a port number.
    pub peer_address: InetSocketAddr,
}

impl<Amt, Bmt, Ti, F> PublicOffer<Amt, Bmt, Ti, F>
where
    Amt: Copy,
    Ti: Copy,
    F: Copy,
{
    pub fn to_arbitrating_params(&self) -> ArbitratingParameters<Amt, Ti, F> {
        ArbitratingParameters {
            arbitrating_amount: self.offer.arbitrating_amount,
            cancel_timelock: self.offer.cancel_timelock,
            punish_timelock: self.offer.punish_timelock,
            fee_strategy: self.offer.fee_strategy,
        }
    }
}

impl<Amt, Bmt, Ti, F> PublicOffer<Amt, Bmt, Ti, F>
where
    Self: Encodable,
{
    /// Generate the public offer [`OfferFingerprint`]. Serialized the public offer (**without
    /// uuid**) and return its keccak hash.
    pub fn fingerprint(&self) -> OfferFingerprint {
        let mut keccak = Keccak::v256();
        let mut out = [0u8; 32];
        let ser = serialize(self);
        keccak.update(&ser[..8]);
        keccak.update(&ser[24..]);
        keccak.finalize(&mut out);
        OfferFingerprint(out)
    }

    /// Returns the hex string representation of the consensus encoded public offer.
    pub fn to_hex(&self) -> String {
        serialize_hex(self)
    }
}

impl<Amt, Bmt, Ti, F> PublicOffer<Amt, Bmt, Ti, F> {
    /// Return the unique offer identifier. Same as [`Self::uuid()`].
    pub fn id(&self) -> Uuid {
        self.uuid()
    }

    /// Return the unique offer identifier.
    pub fn uuid(&self) -> Uuid {
        self.offer.uuid()
    }

    /// Reset offer's uuid with a new identifier.
    pub fn randomize_uuid(&mut self) {
        self.offer.randomize_uuid();
    }

    /// Return the future swap role for the given trade role.
    pub fn swap_role(&self, trade_role: &TradeRole) -> SwapRole {
        self.offer.swap_role(trade_role)
    }
}

impl<Amt, Bmt, Ti, F> Display for PublicOffer<Amt, Bmt, Ti, F>
where
    Self: Encodable,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let encoded = base58_monero::encode_check(consensus::serialize(self).as_ref())
            .expect("Encoding in base58 check works");
        write!(f, "{}{}", PUB_OFFER_PREFIX, encoded)
    }
}

impl<Amt, Bmt, Ti, F> FromStr for PublicOffer<Amt, Bmt, Ti, F>
where
    Amt: CanonicalBytes,
    Bmt: CanonicalBytes,
    Ti: CanonicalBytes,
    F: CanonicalBytes,
{
    type Err = consensus::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if &s[..6] != PUB_OFFER_PREFIX {
            return Err(consensus::Error::IncorrectMagicBytes);
        }
        let decoded = base58_monero::decode_check(&s[6..]).map_err(consensus::Error::new)?;
        let mut res = std::io::Cursor::new(decoded);
        Decodable::consensus_decode(&mut res)
    }
}

impl<Amt, Bmt, Ti, F> Encodable for PublicOffer<Amt, Bmt, Ti, F>
where
    Amt: CanonicalBytes,
    Bmt: CanonicalBytes,
    Ti: CanonicalBytes,
    F: CanonicalBytes,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = OFFER_MAGIC_BYTES.consensus_encode(s)?;
        len += self.version.consensus_encode(s)?;
        len += self.offer.consensus_encode(s)?;
        len += self.node_id.as_canonical_bytes().consensus_encode(s)?;
        len +=
            strict_encoding::StrictEncode::strict_encode(&self.peer_address, s).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Failed to encode InetSocketAddr",
                )
            })?;
        Ok(len)
    }
}

impl<Amt, Bmt, Ti, F> Decodable for PublicOffer<Amt, Bmt, Ti, F>
where
    Amt: CanonicalBytes,
    Bmt: CanonicalBytes,
    Ti: CanonicalBytes,
    F: CanonicalBytes,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let magic_bytes: [u8; 6] = Decodable::consensus_decode(d)?;
        if magic_bytes != *OFFER_MAGIC_BYTES {
            return Err(consensus::Error::IncorrectMagicBytes);
        }
        Ok(PublicOffer {
            version: Decodable::consensus_decode(d)?,
            offer: Decodable::consensus_decode(d)?,
            node_id: PublicKey::from_canonical_bytes(unwrap_vec_ref!(d).as_ref())?,
            peer_address: strict_encoding::StrictDecode::strict_decode(d)
                .map_err(consensus::Error::new)?,
        })
    }
}

impl_strict_encoding!(PublicOffer<Amt, Bmt, Ti, F>, Amt: CanonicalBytes, Bmt: CanonicalBytes, Ti: CanonicalBytes, F: CanonicalBytes,);

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::{
        bitcoin::{fee::SatPerVByte, timelock::CSVTimelock},
        blockchain::Blockchain,
        consensus,
        role::SwapRole,
    };
    use inet2_addr::InetSocketAddr;
    use secp256k1::PublicKey;
    use uuid::uuid;

    const S: &str = "Offer:Cke4ftrP5A7CRkYdGNd87TRU6sUP1kBKM1LQM2fvVdFMNR4gmBqNCsR11111uMM4pF11111112Lvo11111TBALTh113GTvtvqfD1111114A4TUWxWeBc1WxwGBKaUssrb6pnijjhnb6RAs1HBr1CaX7o1a1111111111111111111111111111111111111111115T1WG8uDoZeAW1q";

    lazy_static::lazy_static! {
        pub static ref NODE_ID: PublicKey = {
            let sk =
                bitcoin::util::key::PrivateKey::from_wif("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D")
                    .unwrap()
                    .inner;
            secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk)
        };

        pub static ref PEER_ADDRESS: InetSocketAddr = {
            InetSocketAddr::socket(
                FromStr::from_str("1.2.3.4").unwrap(),
                FromStr::from_str("9735").unwrap(),
            )
        };

        pub static ref OFFER: Offer<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte> = {
            Offer {
                uuid: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
                network: Network::Testnet,
                arbitrating_blockchain: Blockchain::Bitcoin,
                accordant_blockchain: Blockchain::Monero,
                arbitrating_amount: bitcoin::Amount::from_sat(1350),
                accordant_amount: monero::Amount::from_pico(10000),
                cancel_timelock: CSVTimelock::new(4),
                punish_timelock: CSVTimelock::new(6),
                fee_strategy: FeeStrategy::Fixed(SatPerVByte::from_sat(1)),
                maker_role: SwapRole::Bob,
            }
        };
    }

    #[test]
    fn parse_public_offer() {
        let pub_offer =
            PublicOffer::<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte>::from_str(S);
        assert!(pub_offer.is_ok());

        let pub_offer = pub_offer.unwrap();
        assert_eq!(pub_offer.version, Version::new_v1());
        assert_eq!(pub_offer.offer, OFFER.clone());
        assert_eq!(pub_offer.node_id, *NODE_ID);
        assert_eq!(pub_offer.peer_address, *PEER_ADDRESS);
    }

    #[test]
    fn parse_public_offer_fail_without_prefix() {
        let pub_offer =
            PublicOffer::<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte>::from_str(
                &S[5..],
            );
        match pub_offer {
            Err(consensus::Error::IncorrectMagicBytes) => (),
            _ => panic!("Should have return an error IncorrectMagicBytes"),
        }
    }

    #[test]
    fn display_offer() {
        assert_eq!(&format!("{}", *OFFER), "Uuid: 67e55044-10b1-426f-9247-bb680e5fe0c8\nFingerprint: 0xd68b1483de11001050026ca012a2b440818dac23341384c60680f668b52697b0\nNetwork: Testnet\nBlockchain: Bitcoin\n- amount: 0.00001350 BTC\nBlockchain: Monero\n- amount: 0.000000010000 XMR\nTimelocks\n- cancel: 4 blocks\n- punish: 6 blocks\nFee strategy: 1 satoshi/vByte\nMaker swap role: Bob\n");
    }

    #[test]
    fn display_public_offer() {
        let pub_offer = OFFER.clone().to_public_v1(*NODE_ID, *PEER_ADDRESS);
        assert_eq!(&format!("{}", pub_offer), S);
    }

    #[test]
    fn serialize_offer_in_yaml() {
        let offer: Offer<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte> = Offer {
            uuid: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
            network: Network::Testnet,
            arbitrating_blockchain: Blockchain::Bitcoin,
            accordant_blockchain: Blockchain::Monero,
            arbitrating_amount: bitcoin::Amount::from_sat(5),
            accordant_amount: monero::Amount::from_pico(6),
            cancel_timelock: CSVTimelock::new(7),
            punish_timelock: CSVTimelock::new(8),
            fee_strategy: FeeStrategy::Fixed(SatPerVByte::from_sat(9)),
            maker_role: SwapRole::Bob,
        };
        let s = serde_yaml::to_string(&offer).expect("Encode public offer in yaml");
        assert_eq!(
            "---\nuuid: 67e55044-10b1-426f-9247-bb680e5fe0c8\nnetwork: Testnet\narbitrating_blockchain: Bitcoin\naccordant_blockchain: Monero\narbitrating_amount: 0.00000005 BTC\naccordant_amount: 0.000000000006 XMR\ncancel_timelock: 7\npunish_timelock: 8\nfee_strategy:\n  Fixed: 9 satoshi/vByte\nmaker_role: Bob\n",
            s
        );
    }

    #[test]
    fn deserialize_offer_from_yaml() {
        let s = "---\nuuid: 67e55044-10b1-426f-9247-bb680e5fe0c8\nnetwork: Testnet\narbitrating_blockchain: Bitcoin\naccordant_blockchain: Monero\narbitrating_amount: 0.00000005 BTC\naccordant_amount: 0.000000000006 XMR\ncancel_timelock: 7\npunish_timelock: 8\nfee_strategy:\n  Fixed: 9 satoshi/vByte\nmaker_role: Bob\n";
        let offer = serde_yaml::from_str(&s).expect("Decode offer from yaml");
        assert_eq!(
            Offer {
                uuid: uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
                network: Network::Testnet,
                arbitrating_blockchain: Blockchain::Bitcoin,
                accordant_blockchain: Blockchain::Monero,
                arbitrating_amount: bitcoin::Amount::from_sat(5),
                accordant_amount: monero::Amount::from_pico(6),
                cancel_timelock: CSVTimelock::new(7),
                punish_timelock: CSVTimelock::new(8),
                fee_strategy: FeeStrategy::Fixed(SatPerVByte::from_sat(9)),
                maker_role: SwapRole::Bob,
            },
            offer
        );
    }

    #[test]
    fn serialize_public_offer_in_yaml() {
        let public_offer =
            PublicOffer::<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte>::from_str("Offer:Cke4ftrP5A7CRkYdGNd87TRU6sUP1kBKM1W723UjzEWsNR4gmBqNCsR11111uMFubBevJ2E5fp6ZR11111TBALTh113GTvtvqfD1111114A4TTfifktDH7QZD71vpdfo6EVo2ds7KviHz7vYbLZDkgsMNb11111111111111111111111111111111111111111AfZ113XRBuL3QS1m")
            .expect("Valid public offer");
        let s = serde_yaml::to_string(&public_offer).expect("Encode public offer in yaml");
        assert_eq!(
            "---\nversion: 1\noffer:\n  uuid: 67e55044-10b1-426f-9247-bb680e5fe0c8\n  network: Local\n  arbitrating_blockchain: Bitcoin\n  accordant_blockchain: Monero\n  arbitrating_amount: 0.00001350 BTC\n  accordant_amount: 1000000.001000000000 XMR\n  cancel_timelock: 4\n  punish_timelock: 6\n  fee_strategy:\n    Fixed: 1 satoshi/vByte\n  maker_role: Bob\nnode_id: 02e77b779cdc2c713823f7a19147a67e4209c74d77e2cb5045bce0584a6be064d4\npeer_address:\n  IPv4: \"127.0.0.1:9735\"\n",
            s
        );
    }

    #[test]
    fn deserialize_public_offer_from_yaml() {
        let s = "---\nversion: 1\noffer:\n  uuid: 67e55044-10b1-426f-9247-bb680e5fe0c8\n  network: Local\n  arbitrating_blockchain: Bitcoin\n  accordant_blockchain: Monero\n  arbitrating_amount: 0.00001350 BTC\n  accordant_amount: 1000000.001000000000 XMR\n  cancel_timelock: 4\n  punish_timelock: 6\n  fee_strategy:\n    Fixed: 1 satoshi/vByte\n  maker_role: Bob\nnode_id: 02e77b779cdc2c713823f7a19147a67e4209c74d77e2cb5045bce0584a6be064d4\npeer_address:\n  IPv4: \"127.0.0.1:9735\"\n";
        let public_offer = serde_yaml::from_str(&s).expect("Decode public offer from yaml");
        assert_eq!(
            PublicOffer::<bitcoin::Amount, monero::Amount, CSVTimelock, SatPerVByte>::from_str("Offer:Cke4ftrP5A7CRkYdGNd87TRU6sUP1kBKM1W723UjzEWsNR4gmBqNCsR11111uMFubBevJ2E5fp6ZR11111TBALTh113GTvtvqfD1111114A4TTfifktDH7QZD71vpdfo6EVo2ds7KviHz7vYbLZDkgsMNb11111111111111111111111111111111111111111AfZ113XRBuL3QS1m")
                .expect("Valid public offer"),
            public_offer
        );
    }
}
