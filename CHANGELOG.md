# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) as described in [The Cargo Book](https://doc.rust-lang.org/cargo/reference/manifest.html#the-version-field).

## [Unreleased]

## [0.6.3] - 2022-12-28

### Added

- Derive strict encoding for FundingTx (segwit v0) by @TheCharlatan
  ([#320](https://github.com/farcaster-project/farcaster-core/pull/320/files))

## [0.6.2] - 2022-12-28

### Added

- Derive strict encoding for `Alice` (segwit v0), `Bob` (segwit v0), and `KeyManager` by @TheCharlatan ([#318](https://github.com/farcaster-project/farcaster-core/pull/318))

### Changed

- Fee strategy `range` support is now under the new crate feature `fee_range` and disable by default by @h4sh3d ([#314](https://github.com/farcaster-project/farcaster-core/pull/314))
- Change Bitcoin fee unit from `sat/vB` to `sat/kvB` by @h4sh3d ([#315](https://github.com/farcaster-project/farcaster-core/pull/315))

### Fixed

- Check input lenght when parsing deals from strings by @h4sh3d ([#313](https://github.com/farcaster-project/farcaster-core/pull/313)])
- Add estimated witness when computing transaction fee by @h4sh3d ([#317](https://github.com/farcaster-project/farcaster-core/pull/317))

## [0.6.1] - 2022-12-14

### Added

- Implement `FromStr` for `DealId` and `SwapId` by @TheCharlatan ([#307](https://github.com/farcaster-project/farcaster-core/pull/307/files)])
- Derive `PartialOrd` and `Ord` for `Uuid`, `DealId`, and `SwapId` by @TheCharlatan ([#308](https://github.com/farcaster-project/farcaster-core/pull/308))

## [0.6.0] - 2022-12-13

### Added

- `Uuid` wrapper type against `uuid:Uuid` to identify trades and swaps, the wrapper implements strict encoding functionalities by @h4sh3d ([#297](https://github.com/farcaster-project/farcaster-core/pull/297))
- New `DealId` and `SwapId` types wrapping generic `Uuid` by @h4sh3d ([#297](https://github.com/farcaster-project/farcaster-core/pull/297))

### Changed

- Module `negotiation` is renamed as the `trade` module by @h4sh3d and @Lederstrumpf ([#296](https://github.com/farcaster-project/farcaster-core/pull/296))
- `Offer` and `PublicOffer` are renamed `DealParameters` and `Deal`, these structs are used to initialized a swap during the trade setup and should be the outcome of a proper negotiation phase currently out-of-scope for this library by @h4sh3d and @Lederstrumpf ([#296](https://github.com/farcaster-project/farcaster-core/pull/296))
- Deal `uuid` type is switched to a wrapper type by @h4sh3d ([#297](https://github.com/farcaster-project/farcaster-core/pull/297))

### Removed

- `SwapId` is removed and use the new `Uuid` wrapper type by @h4sh3d ([#297](https://github.com/farcaster-project/farcaster-core/pull/297))
- `lightning_encoding` is removed for the protocol messages by @h4sh3d ([#298](https://github.com/farcaster-project/farcaster-core/pull/298))

## [0.5.1] - 2022-08-15

### Added

- Offer `uuid` of type `Uuid` ([#292](https://github.com/farcaster-project/farcaster-core/pull/292))
- Offer and public offer `fingerprint` functions, returns `OfferFingerprint` ([#292](https://github.com/farcaster-project/farcaster-core/pull/292))

### Removed

- `OfferId` and `PublicOfferId` are replaced by the new offer `uuid` and `fingerprint` functions ([#292](https://github.com/farcaster-project/farcaster-core/pull/292))

## [0.5.0] - 2022-07-27

### Added

- Proper serde support on principal types ([#259](https://github.com/farcaster-project/farcaster-core/pull/259))
- Transaction label display and getters ([#260](https://github.com/farcaster-project/farcaster-core/pull/260))
- Impl `From` for timelocks ([#265](https://github.com/farcaster-project/farcaster-core/pull/265))
- Impl some traits to replace node's `Coin` structure with core's `Blockchain` ([#266](https://github.com/farcaster-project/farcaster-core/pull/266))
- More type transformation to ease usage in node ([#275](https://github.com/farcaster-project/farcaster-core/pull/275))
- Re-export concrete types for _Bitcoin-Monero_ swap pair ([#273](https://github.com/farcaster-project/farcaster-core/pull/273))

### Changed

- Replaced `Ctx: Swap` generic context with specific generics ([#255](https://github.com/farcaster-project/farcaster-core/pull/255), [#256](https://github.com/farcaster-project/farcaster-core/pull/256))
- Re-work blockchain management and serialization ([#264](https://github.com/farcaster-project/farcaster-core/pull/264))
- Bump node related dependencies ([#220](https://github.com/farcaster-project/farcaster-core/pull/220), [#281](https://github.com/farcaster-project/farcaster-core/pull/281))
- Bump bitvec to version 1 ([#238](https://github.com/farcaster-project/farcaster-core/pull/238))
- Move to Rust edition 2021 ([#279](https://github.com/farcaster-project/farcaster-core/pull/279))
- Use bytes convertion to keep secpfun compatibility ([#269](https://github.com/farcaster-project/farcaster-core/pull/269))
- Bump MSRV (Minimum Supported Rust Version) from 1.54.0 to 1.59.0

### Fixed

- Fix key manager consensus decodable implementation ([#239](https://github.com/farcaster-project/farcaster-core/pull/239))

### Removed

- `serde` feature is removed and always enabled
- Remove instruction module and general clean up ([#257](https://github.com/farcaster-project/farcaster-core/pull/257), [#271](https://github.com/farcaster-project/farcaster-core/pull/271))

## [0.4.4] - 2022-02-27

### Changed

- Bump lnp/bp dependencies ([#215](https://github.com/farcaster-project/farcaster-core/pull/215))

## [0.4.3] - 2021-12-06

### Added

- Add `strict_encoding` implementation for `PublicOffer` type ([#195](https://github.com/farcaster-project/farcaster-core/pull/197))
- Add `strict_encoding` implementation for `PublicOfferId` type ([#195](https://github.com/farcaster-project/farcaster-core/pull/195))

## [0.4.2] - 2021-12-05

### Added

- Add `"monero"` and `"xmr"` variants for Monero `FromStr` impl ([#192](https://github.com/farcaster-project/farcaster-core/pull/192))
- Add `"bitcoin"` variant for `Bitcoin<Segwit>` implementation of `FromStr` ([#193](https://github.com/farcaster-project/farcaster-core/pull/193))

### Fixed

- Fix `Display` implementation to work with any given writer ([#192](https://github.com/farcaster-project/farcaster-core/pull/192))

## [0.4.1] - 2021-12-05

### Added

- Add `Display` implementation for `Offer` type ([#188](https://github.com/farcaster-project/farcaster-core/pull/188))

### Changed

- Remove `std::Range` from `FeeStrategy` and use custom struct with correct inclusive bound checks ([#189](https://github.com/farcaster-project/farcaster-core/pull/189))
- Improve variants for `FromStr` network parsing ([#184](https://github.com/farcaster-project/farcaster-core/pull/184))

## [0.4.0] - 2021-11-17

### Changed

- Add prefix `Offer` to serialized public offer ([#173](https://github.com/farcaster-project/farcaster-core/pull/173))
- Switch from hex format to base58 (monero) format with checksum verification ([#171](https://github.com/farcaster-project/farcaster-core/pull/171))
- Update monero requirement from 0.15 to 0.16 ([#175](https://github.com/farcaster-project/farcaster-core/pull/175))
- Reimplement serde for `SwapId`, `OfferId` and `PublicOfferId` ([#176](https://github.com/farcaster-project/farcaster-core/pull/176))

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

[Unreleased]: https://github.com/farcaster-project/farcaster-core/compare/v0.6.3...HEAD
[0.6.3]: https://github.com/farcaster-project/farcaster-core/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/farcaster-project/farcaster-core/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/farcaster-project/farcaster-core/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/farcaster-project/farcaster-core/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/farcaster-project/farcaster-core/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/farcaster-project/farcaster-core/compare/v0.4.4...v0.5.0
[0.4.4]: https://github.com/farcaster-project/farcaster-core/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/farcaster-project/farcaster-core/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/farcaster-project/farcaster-core/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/farcaster-project/farcaster-core/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/farcaster-project/farcaster-core/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/farcaster-project/farcaster-core/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/farcaster-project/farcaster-core/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/farcaster-project/farcaster-core/compare/33ed7f975670c79d768d74e3fd5cf7d55e011a18...v0.1.0
