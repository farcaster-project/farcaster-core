//! Tasks used for the daemon to instruct the syncer on what info to track

use std::error;
use thiserror::Error;
use enum_dispatch::enum_dispatch;
use async_trait::async_trait;
use strict_encoding::{StrictEncode, StrictDecode};
use std::fmt;

/// Errors when manipulating tasks
#[derive(Error, Debug)]
pub enum Error {
    /// The task lifetime is expired.
    #[error("Lifetime expired")]
    LifetimeExpired,
    /// Any syncer error not part of this list.
    #[error("Syncer error: {0}")]
    Other(Box<dyn error::Error + Send + Sync>),
}

impl Error {
    /// Creates a new cryptographic error of type other with an arbitrary payload.
    pub fn new<E>(error: E) -> Self
    where
        E: Into<Box<dyn error::Error + Send + Sync>>,
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
    pub fn into_inner(self) -> Option<Box<dyn error::Error + Send + Sync>> {
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


#[async_trait]
#[enum_dispatch]
pub trait Syncer {
    async fn abort(&mut self, task: Abort) -> Result<(), Error>;
    async fn watch_height(&mut self, task: WatchHeight) -> Result<(), Error>;
    async fn watch_address(&mut self, task: WatchAddress) -> Result<(), Error>;
    async fn watch_transaction(&mut self, task: WatchTransaction) -> Result<(), Error>;
    async fn broadcast_transaction(&mut self, task: BroadcastTransaction) -> Result<(), Error>;
    async fn poll(&mut self) -> Result<Vec<Event>, Error>;
}

#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct Abort {
    pub id: i32,
}

impl fmt::Display for Abort {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "abort id {}", self.id)
    }
}

#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct WatchHeight {
    pub id: i32,
    pub lifetime: u64,

    // Additional data, such as which blockchain to watch the height of
    // Useful for networks without a traditional structure
    // Expects serialization before being entered into this struct
    pub addendum: Vec<u8>,
}

impl fmt::Display for WatchHeight {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "watchheight")
    }
}

#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct WatchAddress {
    pub id: i32,
    pub lifetime: u64,
    pub addendum: Vec<u8>,
}

impl fmt::Display for WatchAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "watchaddress")
    }
}

#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct WatchTransaction {
    pub id: i32,
    pub lifetime: u64,
    pub hash: Vec<u8>,
    pub confirmation_bound: u16,
}

impl fmt::Display for WatchTransaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "watchtransaction")
    }
}

#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct BroadcastTransaction {
    pub id: i32,
    pub tx: Vec<u8>,
}

impl fmt::Display for BroadcastTransaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "broadcasttransaction")
    }
}

#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub enum Task {
  Abort(Abort),
  WatchHeight(WatchHeight),
  WatchAddress(WatchAddress),
  WatchTransaction(WatchTransaction),
  BroadcastTransaction(BroadcastTransaction),
}

#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct TaskAborted {
    pub id: i32,
    pub success_abort: i32,
}

impl fmt::Display for TaskAborted {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "taskaborted id {}", 32)
    }
}


#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct HeightChanged {
    pub id: i32,
    pub block: Vec<u8>,
    pub height: u64,
}

impl fmt::Display for HeightChanged {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "heightchanged")
    }
}


#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct AddressTransaction {
    pub id: i32,
    pub hash: Vec<u8>,
    pub amount: u64,
    pub block: Vec<u8>,
}

impl fmt::Display for AddressTransaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "addresstransaction")
    }
}


#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct TransactionConfirmations {
    pub id: i32,
    pub block: Vec<u8>,
    pub confirmations: i32,
}

impl fmt::Display for TransactionConfirmations {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "transactionconfirmations")
    }
}

#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub struct TransactionBroadcasted {
    pub id: i32,
    pub tx_len: i16,
    pub tx: Vec<u8>,
    pub success_broadcast: i32,
}

impl fmt::Display for TransactionBroadcasted {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "transactionbroadcasted")
    }
}

#[derive(Debug, Clone, StrictEncode, StrictDecode)]
pub enum Event {
  HeightChanged(HeightChanged),
  AddressTransaction(AddressTransaction),
  TransactionConfirmations(TransactionConfirmations),
  TransactionBroadcasted(TransactionBroadcasted),
  TaskAborted(TaskAborted),
}
