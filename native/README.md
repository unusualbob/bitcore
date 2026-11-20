# Bitcoin ECDSA for Node

The Bitcoin package can use a local Node-API addon for deterministic secp256k1 signing, verification, and public-key recovery. Existing callers keep using `bitcore.crypto.ECDSA` and the same Bitcore key and signature classes. The Rust ECDSA crate calls Bitcoin Core's libsecp256k1 through the `secp256k1` crate. The Node adapter owns the JavaScript interface. The other coin packages retain their existing implementations.

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

The explicit build places a release binary in `packages/bitcore-lib/lib/native`. Node loads it by default when present. Set `BITCORE_ECDSA_BACKEND=js` to use JavaScript, or `native` to require a loadable addon. Select the backend before importing Bitcore. The npm tarball excludes the local binary, and browser builds use JavaScript. Linux x64 was tested. macOS has linker support but has not been tested. Windows uses JavaScript.

The native path accepts high-S signatures for verification. Signing with `randomK`, or with a digest at or above the curve order, uses Bitcore's JavaScript signer to preserve its nonce behavior. When a caller requests the precise verification error for a rejected signature, the wrapper uses the original point calculation to distinguish an infinite point from other invalid signatures.

The native build and test scripts target Linux and macOS. If the OS cannot supply the entropy needed to blind the signing context, native signing reports an error. A later signing call can retry initialization.

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

A local Cargo release build with an empty target directory and cached dependency sources took 2.98 s. Repeating it took 0.017 s. A comment-only adapter edit rebuilt the adapter in 0.13 s. The same edit in the ECDSA crate rebuilt ECDSA and the adapter in 0.20 s. Cargo reused the compiled cryptographic dependencies in both edit runs.
