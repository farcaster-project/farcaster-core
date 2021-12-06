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
#[cfg(feature = "serde")]
use serde_crate::{de, Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "serde")]
use std::str::FromStr;
use thiserror::Error;
use tiny_keccak::{Hasher, Keccak};

use std::fmt;
use std::io;

use crate::blockchain::{Asset, Fee, FeeStrategy, Network, Timelock};
use crate::consensus::{self, serialize, serialize_hex, CanonicalBytes, Decodable, Encodable};
#[cfg(feature = "serde")]
use crate::hash::{HashString, OfferString};
use crate::role::{SwapRole, TradeRole};
use crate::swap::Swap;

/// First six magic bytes of a public offer. Bytes are included inside the base58 encoded part.
pub const OFFER_MAGIC_BYTES: &[u8; 6] = b"FCSWAP";

/// Prefix for serialized public offer.
pub const PUB_OFFER_PREFIX: &str = "Offer:";

/// A public offer version containing the version and the activated features if any.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Display)]
#[display("v{0}")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
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
    pub struct OfferId(32);
);

#[cfg(feature = "serde")]
impl Serialize for OfferId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(format!("{:#x}", self).as_ref())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for OfferId {
    fn deserialize<D>(deserializer: D) -> Result<OfferId, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            OfferId::from_str(&deserializer.deserialize_string(HashString)?)
                .map_err(de::Error::custom)?,
        )
    }
}

/// An offer is created by a [`TradeRole::Maker`] before the start of his daemon, it references all
/// the data needed to parametrize a trade and be validated from a [`TradeRole::Taker`]
/// perspective. The daemon start when the maker is ready to finalyze his offer, transforming the
/// offer into a [`PublicOffer`] which contains the data needed to a taker to connect to the
/// maker's daemon.
#[derive(Debug, Clone, Eq)]
pub struct Offer<Ctx: Swap> {
    /// Type of offer and network to use.
    pub network: Network,
    /// The chosen arbitrating blockchain.
    pub arbitrating_blockchain: Ctx::Ar,
    /// The chosen accordant blockchain.
    pub accordant_blockchain: Ctx::Ac,
    /// Amount of arbitrating assets to exchanged.
    pub arbitrating_amount: <Ctx::Ar as Asset>::AssetUnit,
    /// Amount of accordant assets to exchanged.
    pub accordant_amount: <Ctx::Ac as Asset>::AssetUnit,
    /// The cancel timelock parameter of the arbitrating blockchain.
    pub cancel_timelock: <Ctx::Ar as Timelock>::Timelock,
    /// The punish timelock parameter of the arbitrating blockchain.
    pub punish_timelock: <Ctx::Ar as Timelock>::Timelock,
    /// The chosen fee strategy for the arbitrating transactions.
    pub fee_strategy: FeeStrategy<<Ctx::Ar as Fee>::FeeUnit>,
    /// The future maker swap role.
    pub maker_role: SwapRole,
}

// https://doc.rust-lang.org/std/hash/trait.Hash.html#hash-and-eq
impl<Ctx: Swap> PartialEq for Offer<Ctx> {
    fn eq(&self, other: &Self) -> bool {
        consensus::serialize_hex(self) == consensus::serialize_hex(other)
    }
}

impl<Ctx: Swap> std::hash::Hash for Offer<Ctx> {
    fn hash<H>(&self, hasher: &mut H)
    where
        H: std::hash::Hasher,
    {
        hasher.write(&consensus::serialize(self)[..]);
    }
}

impl<Ctx: Swap> fmt::Display for Offer<Ctx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

impl<Ctx: Swap> Offer<Ctx> {
    /// Transform the offer in a public offer of [`Version`] 1.
    pub fn to_public_v1(
        self,
        node_id: PublicKey,
        peer_address: InetSocketAddr,
    ) -> PublicOffer<Ctx> {
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

    /// Generate the [`OfferId`] from the offer.
    pub fn id(&self) -> OfferId {
        let mut keccak = Keccak::v256();
        let mut out = [0u8; 32];
        keccak.update(serialize(self).as_ref());
        keccak.finalize(&mut out);
        OfferId(out)
    }
}

impl<Ctx> Encodable for Offer<Ctx>
where
    Ctx: Swap,
{
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.network.consensus_encode(s)?;
        len += self.arbitrating_blockchain.to_u32().consensus_encode(s)?;
        len += self.accordant_blockchain.to_u32().consensus_encode(s)?;
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

impl<Ctx> Decodable for Offer<Ctx>
where
    Ctx: Swap,
{
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Offer {
            network: Decodable::consensus_decode(d)?,
            arbitrating_blockchain: Ctx::Ar::from_u32(Decodable::consensus_decode(d)?)
                .ok_or(consensus::Error::UnknownType)?,
            accordant_blockchain: Ctx::Ac::from_u32(Decodable::consensus_decode(d)?)
                .ok_or(consensus::Error::UnknownType)?,
            arbitrating_amount: <Ctx::Ar as Asset>::AssetUnit::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            accordant_amount: <Ctx::Ac as Asset>::AssetUnit::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            cancel_timelock: <Ctx::Ar as Timelock>::Timelock::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            punish_timelock: <Ctx::Ar as Timelock>::Timelock::from_canonical_bytes(
                unwrap_vec_ref!(d).as_ref(),
            )?,
            fee_strategy: Decodable::consensus_decode(d)?,
            maker_role: Decodable::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(Offer<Ctx>, Ctx: Swap);

/// Helper to create an offer from an arbitrating asset buyer perspective. Only works only for
/// buying [`Arbitrating`] assets with some [`Accordant`] assets.  The reverse is not implemented
/// for the [`Buy`] helper, use the [`Sell`] helper instead.
///
/// [`Arbitrating`]: crate::role::Arbitrating
/// [`Accordant`]: crate::role::Accordant
pub struct Buy<Ctx>(BuilderState<Ctx>)
where
    Ctx: Swap;

impl<Ctx> Buy<Ctx>
where
    Ctx: Swap,
{
    /// Defines the asset and its amount the maker will receive in exchange of the asset and amount
    /// defined in the `with` method.
    pub fn some(asset: Ctx::Ar, amount: <Ctx::Ar as Asset>::AssetUnit) -> Self {
        let mut buy = Self(BuilderState::default());
        buy.0.arbitrating_blockchain = Some(asset);
        buy.0.arbitrating_amount = Some(amount);
        buy
    }

    /// Defines the asset and its amount the maker will send to get the assets defined in the
    /// `some` method.
    pub fn with(mut self, asset: Ctx::Ac, amount: <Ctx::Ac as Asset>::AssetUnit) -> Self {
        self.0.accordant_blockchain = Some(asset);
        self.0.accordant_amount = Some(amount);
        self
    }

    /// Sets the timelocks for the proposed offer.
    pub fn with_timelocks(
        mut self,
        cancel: <Ctx::Ar as Timelock>::Timelock,
        punish: <Ctx::Ar as Timelock>::Timelock,
    ) -> Self {
        self.0.cancel_timelock = Some(cancel);
        self.0.punish_timelock = Some(punish);
        self
    }

    /// Sets the fee strategy for the proposed offer.
    pub fn with_fee(mut self, strategy: FeeStrategy<<Ctx::Ar as Fee>::FeeUnit>) -> Self {
        self.0.fee_strategy = Some(strategy);
        self
    }

    /// Sets the network for the proposed offer.
    pub fn on(mut self, network: Network) -> Self {
        self.0.network = Some(network);
        self
    }

    /// Transform the internal state into an offer if all parameters have been set properly,
    /// otherwise return `None`.
    ///
    /// This function automatically sets the maker swap role as [`SwapRole::Alice`] to comply with
    /// the buy contract.
    pub fn to_offer(mut self) -> Option<Offer<Ctx>> {
        self.0.maker_role = Some(SwapRole::Alice);
        Some(Offer {
            network: self.0.network?,
            arbitrating_blockchain: self.0.arbitrating_blockchain?,
            accordant_blockchain: self.0.accordant_blockchain?,
            arbitrating_amount: self.0.arbitrating_amount?,
            accordant_amount: self.0.accordant_amount?,
            cancel_timelock: self.0.cancel_timelock?,
            punish_timelock: self.0.punish_timelock?,
            fee_strategy: self.0.fee_strategy?,
            maker_role: self.0.maker_role?,
        })
    }
}

/// Helper to create an offer from an arbitrating asset seller perspective. Only works only for
/// selling [`Arbitrating`] assets for some [`Accordant`] assets.  The reverse is not implemented
/// for the [`Sell`] helper, use the [`Buy`] helper instead.
///
/// [`Arbitrating`]: crate::role::Arbitrating
/// [`Accordant`]: crate::role::Accordant
pub struct Sell<Ctx>(BuilderState<Ctx>)
where
    Ctx: Swap;

impl<Ctx> Sell<Ctx>
where
    Ctx: Swap,
{
    /// Defines the asset and its amount the maker will send to get the assets defined in the
    /// `for_some` method.
    pub fn some(asset: Ctx::Ar, amount: <Ctx::Ar as Asset>::AssetUnit) -> Self {
        let mut buy = Self(BuilderState::default());
        buy.0.arbitrating_blockchain = Some(asset);
        buy.0.arbitrating_amount = Some(amount);
        buy
    }

    /// Defines the asset and its amount the maker will receive in exchange of the asset and amount
    /// defined in the `some` method.
    pub fn for_some(mut self, asset: Ctx::Ac, amount: <Ctx::Ac as Asset>::AssetUnit) -> Self {
        self.0.accordant_blockchain = Some(asset);
        self.0.accordant_amount = Some(amount);
        self
    }

    /// Sets the timelocks for the proposed offer.
    pub fn with_timelocks(
        mut self,
        cancel: <Ctx::Ar as Timelock>::Timelock,
        punish: <Ctx::Ar as Timelock>::Timelock,
    ) -> Self {
        self.0.cancel_timelock = Some(cancel);
        self.0.punish_timelock = Some(punish);
        self
    }

    /// Sets the fee strategy for the proposed offer.
    pub fn with_fee(mut self, strategy: FeeStrategy<<Ctx::Ar as Fee>::FeeUnit>) -> Self {
        self.0.fee_strategy = Some(strategy);
        self
    }

    /// Sets the network for the proposed offer.
    pub fn on(mut self, network: Network) -> Self {
        self.0.network = Some(network);
        self
    }

    /// Transform the internal state into an offer if all parameters have been set properly,
    /// otherwise return `None`.
    ///
    /// This function automatically sets the maker swap role as [`SwapRole::Bob`] to comply with
    /// the buy contract.
    pub fn to_offer(mut self) -> Option<Offer<Ctx>> {
        self.0.maker_role = Some(SwapRole::Bob);
        Some(Offer {
            network: self.0.network?,
            arbitrating_blockchain: self.0.arbitrating_blockchain?,
            accordant_blockchain: self.0.accordant_blockchain?,
            arbitrating_amount: self.0.arbitrating_amount?,
            accordant_amount: self.0.accordant_amount?,
            cancel_timelock: self.0.cancel_timelock?,
            punish_timelock: self.0.punish_timelock?,
            fee_strategy: self.0.fee_strategy?,
            maker_role: self.0.maker_role?,
        })
    }
}

// Internal state of an offer builder
struct BuilderState<Ctx: Swap> {
    network: Option<Network>,
    arbitrating_blockchain: Option<Ctx::Ar>,
    accordant_blockchain: Option<Ctx::Ac>,
    arbitrating_amount: Option<<Ctx::Ar as Asset>::AssetUnit>,
    accordant_amount: Option<<Ctx::Ac as Asset>::AssetUnit>,
    cancel_timelock: Option<<Ctx::Ar as Timelock>::Timelock>,
    punish_timelock: Option<<Ctx::Ar as Timelock>::Timelock>,
    fee_strategy: Option<FeeStrategy<<Ctx::Ar as Fee>::FeeUnit>>,
    maker_role: Option<SwapRole>,
}

impl<Ctx> Default for BuilderState<Ctx>
where
    Ctx: Swap,
{
    fn default() -> BuilderState<Ctx> {
        BuilderState {
            network: None,
            arbitrating_blockchain: None,
            accordant_blockchain: None,
            arbitrating_amount: None,
            accordant_amount: None,
            cancel_timelock: None,
            punish_timelock: None,
            fee_strategy: None,
            maker_role: None,
        }
    }
}

fixed_hash::construct_fixed_hash!(
    /// Identify a public offer by it's content, internally store the hash of the offer serialized
    /// with Farcaster consensus.
    pub struct PublicOfferId(32);
);

#[cfg(feature = "serde")]
impl Serialize for PublicOfferId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(format!("{:#x}", self).as_ref())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PublicOfferId {
    fn deserialize<D>(deserializer: D) -> Result<PublicOfferId, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            PublicOfferId::from_str(&deserializer.deserialize_string(HashString)?)
                .map_err(de::Error::custom)?,
        )
    }
}

impl Encodable for PublicOfferId {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(s)
    }
}

impl Decodable for PublicOfferId {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        let bytes: [u8; 32] = Decodable::consensus_decode(d)?;
        Ok(Self::from_slice(&bytes))
    }
}

impl_strict_encoding!(PublicOfferId);

/// A public offer is shared across [`TradeRole::Maker`]'s prefered network to signal is willing of
/// trading some assets at some conditions. The assets and condition are defined in the [`Offer`],
/// maker peer connection information are contained in the public offer.
#[derive(Debug, Clone, Eq)]
pub struct PublicOffer<Ctx: Swap> {
    /// The public offer version.
    pub version: Version,
    /// The content of the offer.
    pub offer: Offer<Ctx>,
    /// Node public key, used both as an ID and encryption key for per-session ECDH.
    pub node_id: PublicKey,
    /// Address of the listening daemon's peer. An internet socket address, which consists of an IP
    /// or Tor address and a port number.
    pub peer_address: InetSocketAddr,
}

impl<Ctx: Swap> PublicOffer<Ctx> {
    /// Generate the [`PublicOfferId`] from the offer. Serialized the public offer with consensus
    /// encoding and return the keccak hash result with [`PublicOfferId`].
    pub fn id(&self) -> PublicOfferId {
        let mut keccak = Keccak::v256();
        let mut out = [0u8; 32];
        keccak.update(serialize(self).as_ref());
        keccak.finalize(&mut out);
        PublicOfferId(out)
    }

    /// Returns the hex string representation of the consensus encoded public offer.
    pub fn to_hex(&self) -> String {
        serialize_hex(&self.clone())
    }
}

// https://doc.rust-lang.org/std/hash/trait.Hash.html#hash-and-eq
impl<Ctx: Swap> PartialEq for PublicOffer<Ctx> {
    fn eq(&self, other: &Self) -> bool {
        consensus::serialize_hex(self) == consensus::serialize_hex(other)
    }
}

impl<Ctx: Swap> std::hash::Hash for PublicOffer<Ctx> {
    fn hash<H>(&self, hasher: &mut H)
    where
        H: std::hash::Hasher,
    {
        hasher.write(&consensus::serialize(self)[..]);
    }
}

impl<Ctx: Swap> PublicOffer<Ctx> {
    /// Return the future swap role for the given trade role.
    pub fn swap_role(&self, trade_role: &TradeRole) -> SwapRole {
        self.offer.swap_role(trade_role)
    }
}

impl<Ctx> std::fmt::Display for PublicOffer<Ctx>
where
    Ctx: Swap,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let encoded = base58_monero::encode_check(consensus::serialize(self).as_ref())
            .expect("Encoding in base58 check works");
        write!(f, "{}{}", PUB_OFFER_PREFIX, encoded)
    }
}

impl<Ctx> std::str::FromStr for PublicOffer<Ctx>
where
    Ctx: Swap,
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

#[cfg(feature = "serde")]
impl<Ctx> Serialize for PublicOffer<Ctx>
where
    Ctx: Swap,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = base58_monero::encode_check(consensus::serialize(self).as_ref())
            .expect("Encoding in base58 check works");
        serializer.serialize_str(encoded.as_ref())
    }
}

#[cfg(feature = "serde")]
impl<'de, Ctx> Deserialize<'de> for PublicOffer<Ctx>
where
    Ctx: Swap,
{
    fn deserialize<D>(deserializer: D) -> Result<PublicOffer<Ctx>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(
            PublicOffer::from_str(&deserializer.deserialize_string(OfferString)?)
                .map_err(de::Error::custom)?,
        )
    }
}

impl<Ctx> Encodable for PublicOffer<Ctx>
where
    Ctx: Swap,
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
                    "Failed to encode RemoteNodeAddr",
                )
            })?;
        Ok(len)
    }
}

impl<Ctx> Decodable for PublicOffer<Ctx>
where
    Ctx: Swap,
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

impl_strict_encoding!(PublicOffer<Ctx>, Ctx: Swap);

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::{
        bitcoin::{fee::SatPerVByte, timelock::CSVTimelock, BitcoinSegwitV0},
        consensus,
        monero::Monero,
        role::SwapRole,
        swap::btcxmr::BtcXmr,
    };
    use inet2_addr::InetSocketAddr;
    use secp256k1::PublicKey;

    const S: &str = "Offer:Cke4ftrP5A71LQM2fvVdFMNR4gmBqNCsR11111uMM4pF11111112Lvo11111TBALTh113GTvtvqfD1111114A4TUWxWeBc1WxwGBKaUssrb6pnijjhnb6RAs1HBr1CaX7o1a1111111111111111111111111111111111111111115T1WG8uDoExnA3T";

    lazy_static::lazy_static! {
        pub static ref NODE_ID: PublicKey = {
            let sk =
                bitcoin::PrivateKey::from_wif("L1HKVVLHXiUhecWnwFYF6L3shkf1E12HUmuZTESvBXUdx3yqVP1D")
                    .unwrap()
                    .key;
            secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &sk)
        };

        pub static ref PEER_ADDRESS: InetSocketAddr = {
            InetSocketAddr::new(
                FromStr::from_str("1.2.3.4").unwrap(),
                FromStr::from_str("9735").unwrap(),
            )
        };

        pub static ref OFFER: Offer<BtcXmr> = {
            Offer {
                network: Network::Testnet,
                arbitrating_blockchain: BitcoinSegwitV0::new(),
                accordant_blockchain: Monero,
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
        let pub_offer = PublicOffer::<BtcXmr>::from_str(S);
        assert!(pub_offer.is_ok());

        let pub_offer = pub_offer.unwrap();
        assert_eq!(pub_offer.version, Version::new_v1());
        assert_eq!(pub_offer.offer, OFFER.clone());
        assert_eq!(pub_offer.node_id, *NODE_ID);
        assert_eq!(pub_offer.peer_address, *PEER_ADDRESS);
    }

    #[test]
    fn parse_public_offer_fail_without_prefix() {
        let pub_offer = PublicOffer::<BtcXmr>::from_str(&S[5..]);
        match pub_offer {
            Err(consensus::Error::IncorrectMagicBytes) => (),
            _ => panic!("Should have return an error IncorrectMagicBytes"),
        }
    }

    #[test]
    fn display_offer() {
        assert_eq!(&format!("{}", *OFFER), "Network: Testnet\nBlockchain: Bitcoin<SegwitV0>\n- amount: 0.00001350 BTC\nBlockchain: Monero\n- amount: 0.000000010000 XMR\nTimelocks\n- cancel: 4 blocks\n- punish: 6 blocks\nFee strategy: Fixed: 1 satoshi/vByte\nMaker swap role: Bob\n");
    }

    #[test]
    fn display_public_offer() {
        let pub_offer = OFFER.clone().to_public_v1(*NODE_ID, *PEER_ADDRESS);
        assert_eq!(&format!("{}", pub_offer), S);
    }
}
