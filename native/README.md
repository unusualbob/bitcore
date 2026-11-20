# Bitcoin cryptography for Node

The Bitcoin package can use a local Node-API addon for deterministic secp256k1 signing, verification, public-key recovery, and key derivation. Existing callers keep using `bitcore.crypto.ECDSA`, `PrivateKey`, `HDPrivateKey`, and `HDPublicKey`. Rust calls Bitcoin Core's libsecp256k1 through the `secp256k1` crate. The Node adapter owns the JavaScript interface. The other coin packages retain their existing implementations.

## Build and test

From the repository root, use the Node version in `.node-version`, installed workspace dependencies, a Rust toolchain, and a C compiler for libsecp256k1.

```sh
node native/build-node.cjs
cargo test --locked --manifest-path native/Cargo.toml -p bitcore-ecdsa
node native/test-binding.cjs
node native/test-parity.cjs
(cd packages/bitcore-lib && BITCORE_ECDSA_BACKEND=native node ../../node_modules/mocha/bin/mocha --recursive --exit)
(cd packages/bitcore-lib && BITCORE_ECDSA_BACKEND=js node ../../node_modules/mocha/bin/mocha --recursive --exit)
node packages/bitcore-lib/benchmark/ecdsa.js
```

The root npm scripts `build:ecdsa`, `test:ecdsa`, and `bench:ecdsa` provide shortcuts for building the addon, running the Rust/binding/parity checks, and benchmarking it.

Use `npm run test:hdkeys` to build and test public-key creation and HD derivation, and `npm run bench:hdkeys` to benchmark those public APIs. Both groups of operations share the addon and its backend selector.

The explicit build places a release binary in `packages/bitcore-lib/lib/native`. Node loads it by default when present. Set `BITCORE_ECDSA_BACKEND=js` to use JavaScript, or `native` to require a loadable addon. Select the backend before importing Bitcore. The npm tarball excludes the local binary, and browser builds use JavaScript. Linux x64 was tested. macOS has linker support but has not been tested. Windows uses JavaScript.

The native path accepts high-S signatures for verification. Signing with `randomK`, or with a digest at or above the curve order, uses Bitcore's JavaScript signer to preserve its nonce behavior. When a caller requests the precise verification error for a rejected signature, the wrapper uses the original point calculation to distinguish an infinite point from other invalid signatures.

The native build and test scripts target Linux and macOS. Signing, converting a private key to a public key, and deriving from a private extended key require OS entropy when the process first initializes the blinded curve context. If entropy is unavailable, the call throws and a later call can retry. This also applies when parsing an extended private key, since Bitcore computes its public key during construction.

The derivation crate handles both standard BIP32 and Bitcore's historical unpadded hardened derivation. For a path such as `m/84'/0'/0'/0/5`, it computes intermediate keys and chain codes in Rust and returns the fields needed to construct the final Bitcore object. The public API still parses paths, checks networks, and serializes extended keys. An older ECDSA-only addon uses JavaScript for derivation.

## Measurements

The benchmark runs both backends through Bitcore's public API in separate Node processes. It alternates execution order across five rounds, warms each operation for at least 250 ms, and measures throughput for at least one second per round. It emits the individual samples, median rates and speedup ratios as JSON. Sixteen hash-derived keys and messages exercise signing, verification with a parsed or serialized key, recovery, and constructing and signing a one-input P2PKH transaction. Compare medians on the same machine.

On Linux x64 with Node 24.22.3, Rust 1.99.1 in release mode, and an Intel Core Ultra 9 275HX, the following medians were measured in operations per second.

| Operation | JavaScript | Native | Speedup |
| --- | ---: | ---: | ---: |
| Sign digest | 2,700 | 59,948 | 22.2× |
| Verify with parsed key | 1,161 | 40,190 | 34.6× |
| Reject invalid signature with parsed key | 1,160 | 40,166 | 34.6× |
| Verify with serialized key | 884 | 3,356 | 3.8× |
| Recover public key | 539 | 3,261 | 6.1× |
| Find recovery factor | 342 | 22,215 | 64.9× |
| Construct and sign P2PKH transaction | 745 | 13,342 | 17.9× |

Median time to require the package in a fresh Node process was 33.4 ms for JavaScript and 34.3 ms for native. The ranges overlapped. Serialized verification includes Bitcore's public-key parser and validation. Public recovery constructs a validated Bitcore public key, while recovery-factor lookup can compare point coordinates directly.

### Public keys and HD wallet derivation

On the same hardware and Node version, `npm run bench:hdkeys` measured these median public-API rates. The fresh-key benchmark constructs a private key and asks for its public key once. The HD benchmarks start with parsed parent keys, as a wallet would when deriving the next address.

| Operation | JavaScript ops/s | Native ops/s | Speedup |
| --- | ---: | ---: | ---: |
| Fresh public key | 2,685 | 66,481 | 24.8× |
| One normal private child | 2,405 | 23,677 | 9.8× |
| One hardened private child | 2,415 | 25,715 | 10.6× |
| One public child | 1,451 | 3,240 | 2.2× |
| Private receive path `m/84'/0'/0'/0/i` | 491 | 15,386 | 31.3× |
| Watch-only path `m/0/i` | 722 | 3,066 | 4.2× |
| Private receive path plus default address serialization | 488 | 13,696 | 28.1× |

### Rebuild scope

ECDSA and HD derivation are sibling crates. Both use a small shared crate for the blinded secp256k1 signing context and the verification context. The Node adapter depends on both. In a local release build with cached dependency sources, Cargo reported the following results after a comment-only edit to each component.

| Change | Workspace crates rebuilt | Elapsed |
| --- | --- | ---: |
| Empty target directory | All crates and dependencies | 3.69 s |
| Repeat build | None | 0.02 s |
| HD derivation | HD derivation and Node adapter | 0.34 s |
| ECDSA | ECDSA and Node adapter | 0.26 s |
| Node adapter | Node adapter | 0.21 s |
