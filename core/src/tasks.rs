//! Tasks used for the daemon to instruct the syncer on what info to track

use enum_dispatch::enum_dispatch;

#[enum_dispatch]
pub trait TaskCore {
    fn id(&self) -> i32;
}

pub struct Abort {
    pub id: i32,
}

impl TaskCore for Abort {
    fn id(&self) -> i32 {
        self.id
    }
}

pub struct WatchHeight<T> {
    pub id: i32,
    pub lifetime: u64,

    // Additional data, such as which blockchain to watch the height of
    // Useful for networks without a traditional structure
    // Uses the default serializer, yet arguably this should return a Vec<u8> and not touch serialization
    pub addendum: T,
}

impl<T> TaskCore for WatchHeight<T> {
    fn id(&self) -> i32 {
        self.id
    }
}

pub struct WatchAddress<T> {
    pub id: i32,
    pub lifetime: u64,
    pub addendum: T,
}

impl<T> TaskCore for WatchAddress<T> {
    fn id(&self) -> i32 {
        self.id
    }
}

pub struct WatchTransaction {
    pub id: i32,
    pub lifetime: u64,
    pub hash: Vec<u8>,
    pub confirmation_bound: u16,
}

impl TaskCore for WatchTransaction {
    fn id(&self) -> i32 {
        self.id
    }
}

pub struct BroadcastTransaction {
    pub id: i32,
    pub tx: Vec<u8>,
}

impl TaskCore for BroadcastTransaction {
    fn id(&self) -> i32 {
        self.id
    }
}

pub enum Task {
  Abort,
  WatchHeight,
  WatchAddress,
  WatchTransaction,
  BroadcastTransaction
}
