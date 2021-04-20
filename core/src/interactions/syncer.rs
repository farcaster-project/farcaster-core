//! Daemon <-> syncer messages

#![allow(dead_code)]

use std::io::Result;

use async_trait::async_trait;
use enum_dispatch::enum_dispatch;

use crate::tasks::*;
use crate::events::Event;

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
