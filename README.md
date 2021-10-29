[![Build Status](https://img.shields.io/github/workflow/status/farcaster-project/farcaster-core/Build/main)](https://github.com/farcaster-project/farcaster-core/actions/workflows/build.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![Crates.io](https://img.shields.io/crates/v/farcaster_core.svg)](https://crates.io/crates/farcaster_core)
[![Documentation](https://docs.rs/farcaster_core/badge.svg)](https://docs.rs/farcaster_core)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
[![MSRV](https://img.shields.io/badge/MSRV-1.54.0-blue)](https://blog.rust-lang.org/2021/07/29/Rust-1.54.0.html)

# Farcaster Core Library
:warning: **This library is a :construction: work in progress :construction: and does not implement everything yet, nor is suitable for production use.**

The Farcaster atomic swaps project core library aim to implement in Rust the following functionnalities needed to build a swap node:

- [x] Swap offers
- [x] Swap roles and trade roles
- [x] Transaction templates implementing on-chain behaviours (arbitration)
- [x] Signature and cryptographic utilities
  - [x] `experimental` ECDSA adaptor signatures (with `ecdsa_fun`)
  - [x] Cross-group discrete logarithm proof system
  - [ ] Schnorr adaptor signature
- [x] Messages exchanged between [farcaster-node](https://github.com/farcaster-project/farcaster-node)'s microservices
- [x] Tasks and blockchain events used by syncers

## Documentation
Currently can be found on [docs.rs/farcaster_core](https://docs.rs/farcaster_core). All possible improvments, to add usage examples and to expand on existing docs would be extremely appreciated.

## Core framework
This library is twofold: providing a flexible framework to add specific blockchain support and implementing these specific blockchain. The framework is accessible in modules at the root of the crate:

- `blockchain`: generic types and constraint traits for on-chain behavior.
- `bundle`: generic types for inter-microservice communication, bonded to arbitrating and accordant traits.
- `consensus`: encoding and decoding implementation for all types in the crate.
- `crypto`: traits and generic types to define cryptographic interactions (wallet capability, commit/reveal scheme, signature and key types, etc).
- `instruction`: types for inter-microservice communication.
- `negotiation`: generic types and utilities for handling the negotiation phase.
- `protocol_message`: generic types exchanged between daemons running a swap toghether.
- `role`: role definition (trade and swap) and implementation over the generic framework.
- `script`: generic types for transaction data management.
- `swap`: swap trait definition, utility types, and swap instance like Btc/Xmr.
- `syncer`: tasks, blockchain events, and errors used by syncers in the microservice architecture.
- `transaction`: transaction traits for building and validating the arbitrating set of transaction.

The blockchain specific support is added under the the following modules:

- `bitcoin`: support for Bitcoin, implementation of all required traits from the framework, e.g. the `Arbitrating` trait in `role` module.
- `monero`: support for Monero, implementation of all required traits from the framework, e.g. the `Accordant` trait in `role` module.
- `swap/btcxmr`: definition of a swap between `bitcoin` and `monero` modules.

### Features
As default the `experimental` feature is enable.

- **serde**: enable serde implementation on some of the types in the library.
- **experimental**: enable experimental cryptography, i.e. not battle tested nor peer reviewed and not intended for production use.
- **taproot**: enable support for Bitcoin Taproot on-chain scripts as the arbitrating engine method.

### Adding blockchain support
To add a blockchain implementation you must implements `Aribtrating` or `Accordant` trait on your blockchain definition, the trait implemented depends on its blockchain on-chain features, see [RFCs](https://github.com/farcaster-project/RFCs) for more details.

To add support for Bitcoin we implement the `Arbitrating` trait on our definition of `Bitcoin`. The implementation contains a strategy allowing variations in SegWit versions or with cryptographic protocols. An `experimental` feature include `SegwitV0` implementation that supports ECDSA for SegWit v0.

```rust
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct Bitcoin<S: Strategy> { ... };

#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct SegwitV0;

impl Strategy for SegwitV0 {}

impl Arbitrating for Bitcoin<SegwitV0> {}
```

The implementation of `Arbitrating` is void but requires a list of other traits (see `src/role.rs`):

```rust
pub trait Arbitrating:
    Asset
    + Address
    + Fee
    + Keys
    + Onchain
    + Signatures
    + Timelock
    + Transactions
    + SharedPrivateKeys
    + ...
{
}
```

By implementing all the required traits on our Bitcoin definition we associate external concrete types used later in the framework logic.

```rust
impl<S: Strategy> blockchain::Asset for Bitcoin<S> {
    /// Type for the traded asset unit for a blockchain.
    type AssetUnit = bitcoin::Amount;

    ...
}

impl<S: Strategy> blockchain::Address for Bitcoin<S> {
    /// Defines the address format for the arbitrating blockchain
    type Address = bitcoin::Address;
}

impl<S: Strategy> blockchain::Timelock for Bitcoin<S> {
    /// Defines the type of timelock used for the arbitrating transactions
    type Timelock = bitcoin::timelock::CSVTimelock;
}
```

Some traits only associate types, some carry more logic such as `Keys` in `crypto` module that defines the type of keys (public and private) and the number of extra keys needed during the swap. This is useful when off-chain cryptographic protocols such as MuSig2 is used in the implementation and requires extra keys, e.g. nonces.

```rust
impl crypto::Keys for Bitcoin<SegwitV0> {
    /// Private key type for the blockchain
    type PrivateKey = bitcoin::PrivateKey;

    /// Public key type for the blockchain
    type PublicKey = bitcoin::PublicKey;

    fn extra_keys() -> Vec<u16> {
        // No extra key
        vec![]
    }
}
```

For an arbitrating implementation transactions are required through `Onchain` and `Transactions` traits, former associate types for partial and final transaction and latter give concrete implementation for every type of transaction.

```rust
impl<S: Strategy> blockchain::Onchain for Bitcoin<S> {
    /// Defines the transaction format used to transfer partial transaction between participant for
    /// the arbitrating blockchain
    type PartialTransaction = bitcoin::PartiallySignedTransaction;

    /// Defines the finalized transaction format for the arbitrating blockchain
    type Transaction = bitcoin::Transaction;
}

impl blockchain::Transactions for Bitcoin<SegwitV0> {
    type Metadata = transaction::MetadataOutput;

    type Funding = Funding;
    type Lock = Tx<Lock>;
    type Buy = Tx<Buy>;
    type Cancel = Tx<Cancel>;
    type Refund = Tx<Refund>;
    type Punish = Tx<Punish>;
}
```

## Releases and Changelog

See [CHANGELOG.md](CHANGELOG.md) and [RELEASING.md](RELEASING.md).

## About
This work is part of the Farcaster cross-chain atomic swap project, see [Farcaster Project](https://github.com/farcaster-project).

## Licensing
The code in this project is licensed under the [LGPL-3.0 License ](LICENSE)
