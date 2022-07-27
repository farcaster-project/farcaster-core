[![Build Status](https://img.shields.io/github/workflow/status/farcaster-project/farcaster-core/Build/main)](https://github.com/farcaster-project/farcaster-core/actions/workflows/build.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![Crates.io](https://img.shields.io/crates/v/farcaster_core.svg)](https://crates.io/crates/farcaster_core)
[![Documentation](https://docs.rs/farcaster_core/badge.svg)](https://docs.rs/farcaster_core)
[![License: LGPL v3](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)
[![MSRV](https://img.shields.io/badge/MSRV-1.59.0-blue)](https://blog.rust-lang.org/2022/02/24/Rust-1.59.0.html)

# Farcaster Core Library

The Farcaster atomic swaps project core library aim to implement in Rust the following functionnalities needed to build a swap node:

- [x] Swap offers (contains all necessary information to start a trade)
- [x] Swap roles and trade roles (who do what during the trade)
- [x] Transaction templates implementing on-chain behaviours (arbitration engine, e.g. on Bitcoin blockchain)
- [x] Signature and cryptographic utilities
  - [x] ECDSA adaptor signatures
  - [x] Cross-group discrete logarithm proof system
  - [ ] Schnorr adaptor signature
- [x] Messages exchanged between [farcaster nodes](https://github.com/farcaster-project/farcaster-node), e.i. the peer-to-peer messages also called _protocol messages_.

## Documentation

Check out the documentation of this library on [docs.rs/farcaster_core](https://docs.rs/farcaster_core). All possible improvments, to add usage examples and to expand on existing docs would be extremely appreciated.

## Core framework

This library is twofold: providing a flexible framework to add specific blockchain support and implementing these specific blockchain (currently _bitcoin_ and _monero_). The framework split in modules at the root of the crate:

- `blockchain`: generic types and traits for declaring assets/chains and on-chain behavior.
- `consensus`: encoding and decoding implementation for all types in the crate, used to serialize and deserialize messages exchanged.
- `crypto`: traits and generic types to define cryptographic interactions (wallet capability, commit/reveal scheme, signature and key types, etc).
- `negotiation`: generic types and utilities for handling the negotiation phase, e.g. creating a public offer.
- `protocol`: generic types related to the execution of the protocol and messages exchanged between peers.
- `role`: role definitions (trade and swap) and trait for the generic framework.
- `script`: generic types for transaction data management.
- `swap`: swap related types and swap concrete instances (e.g. _bitcoin-monero_).
- `transaction`: transaction traits for building and validating the arbitrating set of transaction, e.i. the on-chain engine that guarantees the protocol's game-theory.

The blockchain specific support is added under the the following modules:

- `bitcoin`: support for Bitcoin, implementation of all required traits from the framework, e.g. the `Arbitrating` blockchain role.
- `monero`: support for Monero, implementation of all required traits from the framework, e.g. the `Accordant` blockchain role.
- `swap/btcxmr`: definition of a swap between `bitcoin` and `monero` modules with re-export of the majority of generic types with fixed types associated to `bitcoin` and `monero`.

### Features

As default the `experimental` feature is enable.

- **experimental**: enables experimental cryptography, i.e. not battle tested nor peer reviewed, use it as your own risks.
- **taproot**: [work in progress] enables support for Bitcoin Taproot on-chain scripts as the arbitrating engine method.

### Adding blockchain support

Check `bitcoin`, `monero`, and `swap/btcxmr` modules to see and example of swap pair. For more details on high level context see the [RFCs](https://github.com/farcaster-project/RFCs).

## Releases and Changelog

See [CHANGELOG.md](CHANGELOG.md) and [RELEASING.md](RELEASING.md).

## About

This work is part of the Farcaster cross-chain atomic swap project, see [Farcaster Project](https://github.com/farcaster-project).

## Licensing

The code in this project is licensed under the [LGPL-3.0 License](LICENSE)
