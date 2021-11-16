# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) as described in [The Cargo Book](https://doc.rust-lang.org/cargo/reference/manifest.html#the-version-field).

## [Unreleased]

### Changed

- Add prefix `Offer` to serialized public offer ([#173](https://github.com/farcaster-project/farcaster-core/pull/173))
- Switch from hex format to base58 (monero) format with checksum verification ([#171](https://github.com/farcaster-project/farcaster-core/pull/171))
- Update monero requirement from 0.15 to 0.16 ([#175](https://github.com/farcaster-project/farcaster-core/pull/175))

## [0.3.0] - 2021-11-01

### Added

- Add strict encode + decode for `TxLabel` ([#136](https://github.com/farcaster-project/farcaster-core/issues/136))

### Fixed

- Correct publish been not triggered after release ([#165](https://github.com/farcaster-project/farcaster-core/pull/165))
- Monero network conversion from blockchain network ([#156](https://github.com/farcaster-project/farcaster-core/issues/156))

### Changed

- Update shared workflows ([#165](https://github.com/farcaster-project/farcaster-core/pull/165))
- Rename `recover_accordant_assets` into `recover_accordant_key` ([#154](https://github.com/farcaster-project/farcaster-core/issues/154))

## [0.2.0] - 2021-10-29

### Added

- Workflow automation to manage releases
- Test ser/de strict encoding on protocol messages ([#150](https://github.com/farcaster-project/farcaster-core/pull/150))
- TxLabel::AccLock ([#152](https://github.com/farcaster-project/farcaster-core/pull/152))
- Add build on MSRV 1.54.0 in CI ([#145](https://github.com/farcaster-project/farcaster-core/pull/145))
- Encoding/Decoding support for DLEQ ([#144](https://github.com/farcaster-project/farcaster-core/pull/144))
- DLEQ implementation ([#143](https://github.com/farcaster-project/farcaster-core/pull/143))
- Manage accordant address ([#142](https://github.com/farcaster-project/farcaster-core/pull/142))
- Add correct accordant secret spend management ([#139](https://github.com/farcaster-project/farcaster-core/pull/139))
- Add PartialEq to events ([#134](https://github.com/farcaster-project/farcaster-core/pull/134))
- Taproot and key management ([#126](https://github.com/farcaster-project/farcaster-core/pull/126))
- Auto derive on syncer structs ([#132](https://github.com/farcaster-project/farcaster-core/pull/132))

### Changed

- Cleanup and fix features ([#149](https://github.com/farcaster-project/farcaster-core/pull/149))
- Split out dleq proof from parameters ([#153](https://github.com/farcaster-project/farcaster-core/pull/153))
- Bump dependencies ([#146](https://github.com/farcaster-project/farcaster-core/pull/146), [#147](https://github.com/farcaster-project/farcaster-core/pull/147), [#148](https://github.com/farcaster-project/farcaster-core/pull/148))
- Update Bitcoin and Bitcoincore RPC deps ([#141](https://github.com/farcaster-project/farcaster-core/pull/141))
- Renaming some traits & structs ([#138](https://github.com/farcaster-project/farcaster-core/pull/138))
- Rename and move some files ([#137](https://github.com/farcaster-project/farcaster-core/pull/137))
- Modify segwit0 and extract witness ([#133](https://github.com/farcaster-project/farcaster-core/pull/133))
- RPC tests automation ([#127](https://github.com/farcaster-project/farcaster-core/pull/127/files), [#131](https://github.com/farcaster-project/farcaster-core/pull/131))

### Removed

- Remove public keys from DLEQ proof ([#151](https://github.com/farcaster-project/farcaster-core/pull/151))

## [0.1.0] - 2021-08-24

### Added

- Swap offers
- Swap roles and trade roles
- Basic support for Bitcoin and Monero
- Basic transaction template for `Bitcoin<SegwitV0>`
- **experimental** ECDSA adaptor signatures (with `ecdsa_fun`)
- Messages exchanged between farcaster-node's microservices
- Tasks and blockchain events used by syncers

[Unreleased]: https://github.com/farcaster-project/farcaster-core/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/farcaster-project/farcaster-core/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/farcaster-project/farcaster-core/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/farcaster-project/farcaster-core/compare/33ed7f975670c79d768d74e3fd5cf7d55e011a18...v0.1.0
