//! Daemon <-> syncer messages

#![allow(dead_code)]

use async_trait::async_trait;

use crate::tasks::Task;
use crate::events::Event;

#[async_trait]
pub trait SyncerClient {
    async fn issue(&mut self, task: Task);
}

#[async_trait]
pub trait SyncerServer {
    async fn handle(&mut self, task: Task);
}
