//! Tasks used for the daemon to instruct syncers what state to track on-chain and events returned
//! by syncers to the daemon to update its blockchain state representation.

use std::error;
use std::fmt;
use std::io;

use thiserror::Error;

use crate::consensus::{self, Decodable, Encodable};

/// Errors encountered when manipulating tasks in syncers. [`Self::Other`] can carry out errors
/// from external sources.
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

/// Syncers syncronize swaps with the blockchains by receiving [`Task`], processing them, and
/// producing [`Event`] in return. A [`Task`] while processed can produce any amount of [`Event`]
/// until the task is [`Task::Abort`] or the task completed with its last event.
pub trait Syncer {
    fn abort(&mut self, task: Abort) -> Result<(), Error>;
    fn watch_height(&mut self, task: WatchHeight) -> Result<(), Error>;
    fn watch_address(&mut self, task: WatchAddress) -> Result<(), Error>;
    fn watch_transaction(&mut self, task: WatchTransaction) -> Result<(), Error>;
    fn broadcast_transaction(&mut self, task: BroadcastTransaction) -> Result<(), Error>;
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

/// Tasks created by the daemon and handle by syncers to process a blockchain and generate
/// [`Event`] back to the syncer.
#[derive(Debug, Clone, Display)]
#[display(Debug)]
pub enum Task {
    Abort(Abort),
    WatchHeight(WatchHeight),
    WatchAddress(WatchAddress),
    WatchTransaction(WatchTransaction),
    BroadcastTransaction(BroadcastTransaction),
}

impl Encodable for Task {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        match self {
            Task::Abort(t) => {
                let len = 0x01u8.consensus_encode(s)?;
                Ok(len + t.consensus_encode(s)?)
            }
            Task::WatchHeight(t) => {
                let len = 0x02u8.consensus_encode(s)?;
                Ok(len + t.consensus_encode(s)?)
            }
            Task::WatchAddress(t) => {
                let len = 0x03u8.consensus_encode(s)?;
                Ok(len + t.consensus_encode(s)?)
            }
            Task::WatchTransaction(t) => {
                let len = 0x04u8.consensus_encode(s)?;
                Ok(len + t.consensus_encode(s)?)
            }
            Task::BroadcastTransaction(t) => {
                let len = 0x05u8.consensus_encode(s)?;
                Ok(len + t.consensus_encode(s)?)
            }
        }
    }
}

impl Decodable for Task {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u8 => Ok(Task::Abort(Decodable::consensus_decode(d)?)),
            0x02u8 => Ok(Task::WatchHeight(Decodable::consensus_decode(d)?)),
            0x03u8 => Ok(Task::WatchAddress(Decodable::consensus_decode(d)?)),
            0x04u8 => Ok(Task::WatchTransaction(Decodable::consensus_decode(d)?)),
            0x05u8 => Ok(Task::BroadcastTransaction(Decodable::consensus_decode(d)?)),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl_strict_encoding!(Task);

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

/// Events returned by syncers to the daemon to update the blockchain states.  Events are
/// identified with a unique 32-bits integer that match the [`Task`] id.
#[derive(Debug, Clone, Display)]
#[display(Debug)]
pub enum Event {
    /// Notify the daemon the blockchain height changed.
    HeightChanged(HeightChanged),
    AddressTransaction(AddressTransaction),
    TransactionConfirmations(TransactionConfirmations),
    TransactionBroadcasted(TransactionBroadcasted),
    /// Notify the daemon the task has been aborted with success or failure. Carries the status for
    /// the task abortion.
    TaskAborted(TaskAborted),
}

impl Encodable for Event {
    fn consensus_encode<W: io::Write>(&self, s: &mut W) -> Result<usize, io::Error> {
        match self {
            Event::HeightChanged(t) => {
                let len = 0x01u8.consensus_encode(s)?;
                Ok(len + t.consensus_encode(s)?)
            }
            Event::AddressTransaction(t) => {
                let len = 0x02u8.consensus_encode(s)?;
                Ok(len + t.consensus_encode(s)?)
            }
            Event::TransactionConfirmations(t) => {
                let len = 0x03u8.consensus_encode(s)?;
                Ok(len + t.consensus_encode(s)?)
            }
            Event::TransactionBroadcasted(t) => {
                let len = 0x04u8.consensus_encode(s)?;
                Ok(len + t.consensus_encode(s)?)
            }
            Event::TaskAborted(t) => {
                let len = 0x05u8.consensus_encode(s)?;
                Ok(len + t.consensus_encode(s)?)
            }
        }
    }
}

impl Decodable for Event {
    fn consensus_decode<D: io::Read>(d: &mut D) -> Result<Self, consensus::Error> {
        match Decodable::consensus_decode(d)? {
            0x01u8 => Ok(Event::HeightChanged(Decodable::consensus_decode(d)?)),
            0x02u8 => Ok(Event::AddressTransaction(Decodable::consensus_decode(d)?)),
            0x03u8 => Ok(Event::TransactionConfirmations(
                Decodable::consensus_decode(d)?,
            )),
            0x04u8 => Ok(Event::TransactionBroadcasted(Decodable::consensus_decode(
                d,
            )?)),
            0x05u8 => Ok(Event::TaskAborted(Decodable::consensus_decode(d)?)),
            _ => Err(consensus::Error::UnknownType),
        }
    }
}

impl_strict_encoding!(Event);

#[test]
fn test_event_encoding() {
    let height_changed = HeightChanged {
        id: 32131,
        block: vec![1; 32],
        height: 42,
    };
    let event = Event::HeightChanged(height_changed);
    let mut encoder = Vec::new();
    event.consensus_encode(&mut encoder).unwrap();
    let mut res = std::io::Cursor::new(encoder.clone());
    let event_decoded = Event::consensus_decode(&mut res).unwrap();
    match event_decoded {
        Event::HeightChanged(height_changed) => {
            assert_eq!(height_changed.height, 42);
        }
        _ => {
            panic!("expected height changed event")
        }
    }

    let transaction_broadcasted = TransactionBroadcasted {
        id: 12312,
        tx_len: 05,
        tx: vec![42, 42, 42, 42, 42],
        success_broadcast: 1,
    };
    let event_broadcasted = Event::TransactionBroadcasted(transaction_broadcasted);
    let mut encoding = Vec::new();
    event_broadcasted.consensus_encode(&mut encoding).unwrap();
    let mut res_broad = std::io::Cursor::new(encoding.clone());
    let broadcasted_decoded = Event::consensus_decode(&mut res_broad).unwrap();
    match broadcasted_decoded {
        Event::TransactionBroadcasted(transaction_broadcasted) => {
            assert_eq!(transaction_broadcasted.id, 12312);
        }
        _ => {
            panic!("expected transaction broadcasted event")
        }
    }
}
