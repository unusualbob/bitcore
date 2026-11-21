# Bitcore cryptography for Node

Bitcore’s optional Rust addon accelerates cryptography through the existing Node APIs for Bitcoin, Bitcoin Cash, Litecoin, Dogecoin, EVM chains, XRP and Solana. The [performance report](PERFORMANCE.md) compares this branch with upstream master and lists the operations covered on each chain. The [RPC report](RPC-COVERAGE.md) describes which operations run locally and which run in a daemon or provider.

## Build and test

From the repository root, use the Node version in [`.node-version`](../.node-version), installed workspace dependencies, Rust 1.85 or later, Cargo and a C compiler for libsecp256k1.

| Task | Command |
| --- | --- |
| Build the release addon for local use | `npm run build:crypto` |
| Run the Rust workspace tests, build the addon, compile the TypeScript fixtures’ dependencies and run cross-chain parity checks | `npm run test:crypto` |
| Test one component | `npm run test:ecdsa`, `test:hdkeys`, `test:taproot`, `test:forks` or `test:kdfs` (each via `npm run`) |

The build installs the same binary as `lib/native/bitcore_ecdsa.node` in each of the four Bitcoin-family packages. npm tarballs exclude the locally built binary. Browser bundles use the JavaScript backend. Linux x64 is the tested native platform. The build includes macOS linker support for macOS, which is unverified. On Windows, use the fallback.

## Select a backend

Set the environment variable before importing the library. Bitcoin uses `BITCORE_ECDSA_BACKEND`. Bitcoin Cash, Litecoin and Dogecoin use `BITCORE_BCH_BACKEND`, `BITCORE_LTC_BACKEND` and `BITCORE_DOGE_BACKEND` respectively.

| Value | Behavior |
| --- | --- |
| `auto` | Load a compatible addon when available. A missing binary falls back silently. An incompatible ABI or failed dynamic load warns and falls back. |
| `js` | Skip the Bitcore addon. Existing Node crypto and SDK implementations remain available. |
| `native` | Require a compatible addon at import time. Individual operations can still use their fallback for unsupported inputs or missing exports on an older addon. |

Bitcoin defaults to `auto`. Each fork honors its own selector first. With no fork selector, it inherits a global `js` setting and otherwise uses `auto`. To require native loading for all four packages, set all four selectors to `native`.

## Compatibility and rebuilds

- **ECDSA.** Bitcore verification accepts high-S signatures. Deterministic signing preserves the original nonce behavior for digests at or above the curve order. With `randomK`, Bitcore’s existing randomness source supplies each nonce candidate. [ECDSA implementation](../packages/bitcore-lib/lib/crypto/ecdsa.js)
- **Schnorr and key parsing.** Bitcoin Taproot signing preserves Bitcore’s minimal-integer encoding in nonce generation. Bitcoin Cash uses its separate 2019 Schnorr scheme. Irregular SEC encodings that the native parser declines go through the existing Bitcore parser. [Taproot](crates/taproot/src/lib.rs) · [BCH Schnorr](crates/bch-schnorr/src/lib.rs)
- **HD keys.** Native derivation supports standard BIP32 and Bitcore’s historical unpadded hardened derivation. The JavaScript API still parses paths, checks networks and constructs the returned key objects. Initializing the blinded secp256k1 context for private-key operations requires OS entropy. Initialization can retry after an entropy failure. [HD derivation](crates/hdkeys/src/lib.rs) · [Curve context](crates/secp-context/src/lib.rs)
- **Rebuild scope.** The algorithms live in separate Cargo crates behind one Node-API adapter. With cached dependencies, editing the Base58 crate rebuilds Base58 and the adapter. Editing a shared crate such as the curve context also rebuilds its dependents. [Workspace](Cargo.toml) · [Adapter dependencies](crates/node/Cargo.toml)

For focused measurements of ECDSA recovery, HD derivation, Taproot primitives and complete TSS sessions, the root package provides `bench:ecdsa`, `bench:hdkeys`, `bench:taproot` and `bench:tss`. These measure the selected implementations within a checkout. For comparisons between revisions, use the fixtures and commands in the [performance report](PERFORMANCE.md).
