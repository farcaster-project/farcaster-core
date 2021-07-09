//! Tasks used for the daemon to instruct the syncer on what info to track

use std::error;
use std::fmt;
use std::io;

use thiserror::Error;

use crate::consensus::{self, Decodable, Encodable};

/// Errors when manipulating tasks
#[derive(Error, Debug)]
pub enum Error {
    /// The task lifetime is expired.
    #[error("Lifetime expired")]
    LifetimeExpired,
    /// Any syncer error not part of this list.
    #[error("Syncer error: {0}")]
    Other(Box<dyn error::Error>),
}

impl Error {
    /// Creates a new cryptographic error of type other with an arbitrary payload.
    pub fn new<E>(error: E) -> Self
    where
        E: Into<Box<dyn error::Error>>,
    {
        Self::Other(error.into())
    }

    /// Consumes the `Error`, returning its inner error (if any).
    ///
    /// If this [`enum@Error`] was constructed via [`new`] then this function will return [`Some`],
    /// otherwise it will return [`None`].
    ///
    /// [`new`]: Error::new
    ///
    pub fn into_inner(self) -> Option<Box<dyn error::Error>> {
        match self {
            Self::Other(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Other(Box::new(err))
    }
}

pub trait Syncer {
    fn abort(&mut self, task: Abort) -> Result<(), Error>;
    fn watch_height(&mut self, task: WatchHeight) -> Result<(), Error>;
    fn watch_address(&mut self, task: WatchAddress) -> Result<(), Error>;
    fn watch_transaction(&mut self, task: WatchTransaction) -> Result<(), Error>;
    fn broadcast_transaction(&mut self, task: BroadcastTransaction) -> Result<(), Error>;
    fn poll(&mut self) -> Result<Vec<Event>, Error>;
}

#[derive(Debug, Clone)]
pub struct Abort {
    pub id: i32,
}

impl Encodable for Abort {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        self.id.consensus_encode(s)
    }
}

impl Decodable for Abort {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            id: i32::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(Abort);

impl fmt::Display for Abort {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "abort id {}", self.id)
    }
}

#[derive(Debug, Clone)]
pub struct WatchHeight {
    pub id: i32,
    pub lifetime: u64,

    // Additional data, such as which blockchain to watch the height of
    // Useful for networks without a traditional structure
    // Expects serialization before being entered into this struct
    pub addendum: Vec<u8>,
}

impl Encodable for WatchHeight {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.id.consensus_encode(s)?;
        len += self.lifetime.consensus_encode(s)?;
        Ok(len + self.addendum.consensus_encode(s)?)
    }
}

impl Decodable for WatchHeight {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            id: i32::consensus_decode(d)?,
            lifetime: u64::consensus_decode(d)?,
            addendum: Vec::<u8>::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(WatchHeight);

impl fmt::Display for WatchHeight {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "watchheight")
    }
}

#[derive(Debug, Clone)]
pub struct WatchAddress {
    pub id: i32,
    pub lifetime: u64,
    pub addendum: Vec<u8>,
}

impl Encodable for WatchAddress {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.id.consensus_encode(s)?;
        len += self.lifetime.consensus_encode(s)?;
        Ok(len + self.addendum.consensus_encode(s)?)
    }
}

impl Decodable for WatchAddress {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            id: i32::consensus_decode(d)?,
            lifetime: u64::consensus_decode(d)?,
            addendum: Vec::<u8>::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(WatchAddress);

impl fmt::Display for WatchAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "watchaddress")
    }
}

#[derive(Debug, Clone)]
pub struct WatchTransaction {
    pub id: i32,
    pub lifetime: u64,
    pub hash: Vec<u8>,
    pub confirmation_bound: u16,
}

impl Encodable for WatchTransaction {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.id.consensus_encode(s)?;
        len += self.lifetime.consensus_encode(s)?;
        len += self.hash.consensus_encode(s)?;
        Ok(len + self.confirmation_bound.consensus_encode(s)?)
    }
}

impl Decodable for WatchTransaction {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            id: i32::consensus_decode(d)?,
            lifetime: u64::consensus_decode(d)?,
            hash: Vec::<u8>::consensus_decode(d)?,
            confirmation_bound: u16::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(WatchTransaction);

impl fmt::Display for WatchTransaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "watchtransaction")
    }
}

#[derive(Debug, Clone)]
pub struct BroadcastTransaction {
    pub id: i32,
    pub tx: Vec<u8>,
}

impl Encodable for BroadcastTransaction {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let len = self.id.consensus_encode(s)?;
        Ok(len + self.tx.consensus_encode(s)?)
    }
}

impl Decodable for BroadcastTransaction {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            id: i32::consensus_decode(d)?,
            tx: Vec::<u8>::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(BroadcastTransaction);

impl fmt::Display for BroadcastTransaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "broadcasttransaction")
    }
}

#[derive(Debug, Clone)]
pub enum Task {
    Abort(Abort),
    WatchHeight(WatchHeight),
    WatchAddress(WatchAddress),
    WatchTransaction(WatchTransaction),
    BroadcastTransaction(BroadcastTransaction),
}

#[derive(Debug, Clone)]
pub struct TaskAborted {
    pub id: i32,
    pub success_abort: i32,
}

impl Encodable for TaskAborted {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let len = self.id.consensus_encode(s)?;
        Ok(len + self.success_abort.consensus_encode(s)?)
    }
}

impl Decodable for TaskAborted {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            id: i32::consensus_decode(d)?,
            success_abort: i32::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(TaskAborted);

impl fmt::Display for TaskAborted {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "taskaborted id {}", 32)
    }
}

#[derive(Debug, Clone)]
pub struct HeightChanged {
    pub id: i32,
    pub block: Vec<u8>,
    pub height: u64,
}

impl Encodable for HeightChanged {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.id.consensus_encode(s)?;
        len += self.block.consensus_encode(s)?;
        Ok(len + self.height.consensus_encode(s)?)
    }
}

impl Decodable for HeightChanged {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            id: i32::consensus_decode(d)?,
            block: Vec::<u8>::consensus_decode(d)?,
            height: u64::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(HeightChanged);

impl fmt::Display for HeightChanged {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "heightchanged")
    }
}

#[derive(Debug, Clone)]
pub struct AddressTransaction {
    pub id: i32,
    pub hash: Vec<u8>,
    pub amount: u64,
    pub block: Vec<u8>,
}

impl Encodable for AddressTransaction {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.id.consensus_encode(s)?;
        len += self.hash.consensus_encode(s)?;
        len += self.amount.consensus_encode(s)?;
        Ok(len + self.block.consensus_encode(s)?)
    }
}

impl Decodable for AddressTransaction {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            id: i32::consensus_decode(d)?,
            hash: Vec::<u8>::consensus_decode(d)?,
            amount: u64::consensus_decode(d)?,
            block: Vec::<u8>::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(AddressTransaction);

impl fmt::Display for AddressTransaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "addresstransaction")
    }
}

#[derive(Debug, Clone)]
pub struct TransactionConfirmations {
    pub id: i32,
    pub block: Vec<u8>,
    pub confirmations: i32,
}

impl Encodable for TransactionConfirmations {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.id.consensus_encode(s)?;
        len += self.block.consensus_encode(s)?;
        Ok(len + self.confirmations.consensus_encode(s)?)
    }
}

impl Decodable for TransactionConfirmations {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            id: i32::consensus_decode(d)?,
            block: Vec::<u8>::consensus_decode(d)?,
            confirmations: i32::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(TransactionConfirmations);

impl fmt::Display for TransactionConfirmations {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "transactionconfirmations")
    }
}

#[derive(Debug, Clone)]
pub struct TransactionBroadcasted {
    pub id: i32,
    pub tx_len: i16,
    pub tx: Vec<u8>,
    pub success_broadcast: i32,
}

impl Encodable for TransactionBroadcasted {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        let mut len = self.id.consensus_encode(s)?;
        len += self.tx_len.consensus_encode(s)?;
        len += self.tx.consensus_encode(s)?;
        Ok(len + self.success_broadcast.consensus_encode(s)?)
    }
}

impl Decodable for TransactionBroadcasted {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        Ok(Self {
            id: i32::consensus_decode(d)?,
            tx_len: i16::consensus_decode(d)?,
            tx: Vec::<u8>::consensus_decode(d)?,
            success_broadcast: i32::consensus_decode(d)?,
        })
    }
}

impl_strict_encoding!(TransactionBroadcasted);

impl fmt::Display for TransactionBroadcasted {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "transactionbroadcasted")
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    HeightChanged(HeightChanged),
    AddressTransaction(AddressTransaction),
    TransactionConfirmations(TransactionConfirmations),
    TransactionBroadcasted(TransactionBroadcasted),
    TaskAborted(TaskAborted),
}
