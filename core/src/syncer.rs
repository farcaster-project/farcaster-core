//! Tasks used for the daemon to instruct the syncer on what info to track

// #![allow(dead_code)]

use std::io::Result;
use enum_dispatch::enum_dispatch;
use async_trait::async_trait;

#[async_trait]
#[enum_dispatch]
pub trait Syncer {
    async fn abort(&mut self, task: Abort);
    async fn watch_height(&mut self, task: WatchHeight);
    async fn watch_address(&mut self, task: WatchAddress) -> Result<()>;
    async fn watch_transaction(&mut self, task: WatchTransaction) -> Result<()>;
    async fn broadcast_transaction(&mut self, task: BroadcastTransaction) -> Result<()>;
    async fn poll(&mut self) -> Result<Vec<Event>>;
}

// #[enum_dispatch]
// pub trait TaskCore {
    // fn id(&self) -> i32 {
        // self.id
    // }
// }

#[derive(Debug, Clone)]
pub struct Abort {
    pub id: i32,
}

// impl TaskCore for Abort {}

#[derive(Debug, Clone)]
pub struct WatchHeight {
    pub id: i32,
    pub lifetime: u64,

    // Additional data, such as which blockchain to watch the height of
    // Useful for networks without a traditional structure
    // Expects serialization before being entered into this struct
    pub addendum: Vec<u8>,
}

// impl TaskCore for WatchHeight {}

#[derive(Debug, Clone)]
pub struct WatchAddress {
    pub id: i32,
    pub lifetime: u64,
    pub addendum: Vec<u8>,
}

// impl TaskCore for WatchAddress {}

#[derive(Debug, Clone)]
pub struct WatchTransaction {
    pub id: i32,
    pub lifetime: u64,
    pub hash: Vec<u8>,
    pub confirmation_bound: u16,
}

// impl TaskCore for WatchTransaction {}

#[derive(Debug, Clone)]
pub struct BroadcastTransaction {
    pub id: i32,
    pub tx: Vec<u8>,
}

// impl TaskCore for BroadcastTransaction {}

// #[enum_dispatch(TaskCore)]
#[derive(Debug, Clone)]
pub enum Task {
  Abort,
  WatchHeight,
  WatchAddress,
  WatchTransaction,
  BroadcastTransaction,
}

// pub trait EventCore {
    // id: i32;
    // fn id(&self) -> i32 {
        // self.id
    // }
// }

#[derive(Debug, Clone)]
pub struct HeightChanged {
    pub id: i32,
    pub block: Vec<u8>,
    pub height: u64,
}

// impl EventCore for HeightChanged {}

#[derive(Debug, Clone)]
pub struct AddressTransaction {
    pub id: i32,
    pub hash: Vec<u8>,
    pub amount: String,
    pub block: Vec<u8>,
}

// impl EventCore for AddressTransaction {}

#[derive(Debug, Clone)]
pub struct TransactionConfirmations {
    pub id: i32,
    pub block: Vec<u8>,
    pub confirmations: i32,
}

// impl EventCore for TransactionConfirmations {}

#[derive(Debug, Clone)]
pub struct TransactionBroadcasted {
    pub id: i32,
    pub tx_len: i16,
    pub tx: Vec<u8>,
    pub success_broadcast: i32,
}

// impl EventCore for TransactionBroadcasted {}

// #[enum_dispatch(EventCore)]
#[derive(Debug, Clone)]
pub enum Event {
  HeightChanged,
  AddressTransaction,
  TransactionConfirmations,
  TransactionBroadcasted,
}
