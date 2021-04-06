#![allow(dead_code)]

use farcaster_core::tasks;

struct Empty;
type BtcWatchHeight = tasks::WatchHeight<Empty>;

pub struct BtcAddressAddendum {
    address: String,
    from_height: u64,
}
type BtcWatchAddress = tasks::WatchAddress<BtcAddressAddendum>;
