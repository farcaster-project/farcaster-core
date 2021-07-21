[![Build Status](https://img.shields.io/github/workflow/status/farcaster-project/farcaster-core/CI/main)](https://github.com/farcaster-project/farcaster-core/actions/workflows/ci.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![Crates.io](https://img.shields.io/crates/v/farcaster_core.svg)](https://crates.io/crates/farcaster_core)
[![Documentation](https://docs.rs/farcaster_core/badge.svg)](https://docs.rs/farcaster_core)

# Farcaster Core Library
Farcaster atomic swaps project core library implementing in Rust:

:warning: **This library is a :construction: work in progress :construction: and does not implement everything yet, nor is suitable for production use**

- [x] Farcaster swap offers
- [x] Swap roles and trade roles
- [x] Transactions templates to implement on-chain behaviours
- [ ] Signature and cryptographic utilities
- [x] Messages exchanged between [farcaster-node](https://github.com/farcaster-project/farcaster-node)'s microservices
- [ ] Tasks and blockchain events used by syncers

## Core framework
This library is twofold: providing a flexible framework to add specific blockchain support and implementing these specific blockchain. The framework is accessible in all module at the root of the crate:

- `blockchain`: generic types and constraint traits for on-chain behavior.
- `bundle`: generic types for inter-microservice communication, bonds to arbitrating and accordant traits.
- `consensus`: encoding and decoding implementation for all types in the crate.
- `crypto`: traits and generic types to define cryptographic interactions (wallet capability, commit/reveal scheme, signature and key types, etc).
- `events`: generic types and definition of blockchain events fired by syncers in the microservice architecture.
- `instruction`: generic types for inter-microservice communication.
- `negotiation`: generic types and utilities for handling the negotiation phase.
- `protocol_message`: generic types exchanged between daemon running a swap toghether.
- `role`: role definition (trade and swap) and implementation over the generic framework.
- `script`: generic types for transaction data management.
- `swap`: swap trait definition and utility types.
- `syncer`: generic task types and errors.
- `transaction`: transaction traits to implement for building and validating the arbitrating set of transaction.

The blockchain specific support is added under the `chain` module.

- `chain/bitcoin`: support for Bitcoin, implementation of all required traits from the framework, e.g. the `Arbitrating` trait in `role` module.
- `chain/monero`: support for Monero, implementation of all required traits from the framework, e.g. the `Accordant` trait in `role` module.
- `chain/pairs/btcxmr`: definition of a swap between Bitcoin from `chain/bitcoin` and Monero from `chain/monero`.

### Adding blockchain support
To add a blockchain implementation you must implements `Aribtrating` or `Accordant` trait on your blockchain definition, the trait implemented depends on its blockchain on-chain features, see [RFCs](https://github.com/farcaster-project/RFCs) for more details.

To add support for Bitcoin we implement the `Arbitrating` trait on our definition of `Bitcoin`.

```rust
#[derive(Clone, Debug, Copy, Eq, PartialEq)]
pub struct Bitcoin { ... };

impl Arbitrating for Bitcoin {}
```

The implementation is void but requires a list of traits such as (see `src/role.rs`):

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
    + Clone
    + Eq
{
}
```

By implementing all the required traits on Bitcoin we associate Bitcoin external concrete types used in the framework logic.

```rust
impl blockchain::Asset for Bitcoin {
    /// Type for the traded asset unit for a blockchain.
    type AssetUnit = bitcoin::Amount;

    ...
}

impl blockchain::Address for Bitcoin {
    /// Defines the address format for the arbitrating blockchain
    type Address = bitcoin::Address;
}

impl blockchain::Timelock for Bitcoin {
    /// Defines the type of timelock used for the arbitrating transactions
    type Timelock = bitcoin::timelock::CSVTimelock;
}
```

Some traits only associate types, some carry more logic such as `Keys` in `crypto` module that defines the type of keys (public and private) and the number of extra keys needed during the swap. This is useful when off-chain cryptographic protocols such as MuSig2 is used in the implementation and requires extra keys, e.g. nonces.

```rust
impl crypto::Keys for Bitcoin {
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
impl blockchain::Onchain for Bitcoin {
    /// Defines the transaction format used to transfer partial transaction between participant for
    /// the arbitrating blockchain
    type PartialTransaction = bitcoin::PartiallySignedTransaction;

    /// Defines the finalized transaction format for the arbitrating blockchain
    type Transaction = bitcoin::Transaction;
}

impl blockchain::Transactions for Bitcoin {
    type Metadata = transaction::MetadataOutput;

    type Funding = Funding;
    type Lock = Tx<Lock>;
    type Buy = Tx<Buy>;
    type Cancel = Tx<Cancel>;
    type Refund = Tx<Refund>;
    type Punish = Tx<Punish>;
}
```

# About

This work is part of the Farcaster cross-chain atomic swap project, see [Farcaster Project](https://github.com/farcaster-project).
