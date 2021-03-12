//! Farcaster instructions sent between client and daemon to instruct what to do next in the swap
//! process.

pub trait Instruction {}

/// Provides deamon the instruction to abort the swap, it is the daemon responsability to abort
/// accordingly to the current state swap. By transmitting latter feedback via `state digest`, the
/// client must be able to provide any missing signatures.
pub struct Abort {
    /// OPTIONAL: A code conveying the reason of the abort
    pub abort_code: Option<u16>,
}

impl Instruction for Abort {}

/// Provides deamon the instruction to follow the protocol swap, daemon can create locking steps
/// during the protocol execution and require client to acknoledge the execution progression.
pub struct Next {
    /// OPTIONAL: A code conveying the type of execution progression
    pub next_code: Option<u16>,
}

impl Instruction for Next {}
