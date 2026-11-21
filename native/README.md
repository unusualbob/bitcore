# Bitcore cryptography for Node

Bitcore's optional Node-API addon accelerates the wallet libraries across UTXO, EVM, XRP and Solana chains. Existing callers use the same Bitcore classes and methods. The [chain coverage and measurements](COVERAGE.md) describe the wallet, transaction, RPC and service paths. The sections below also record results from earlier migration phases.

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

For the full cross-chain checks, run `npm run test:crypto`. It tests the Rust workspace, builds the release addon, compiles the TypeScript packages used by the fixtures, and runs the parity suites through the library, RPC and wallet APIs. The root npm scripts `build:ecdsa`, `test:ecdsa`, and `bench:ecdsa` remain available for the original ECDSA workflow.

Use `npm run test:hdkeys` to build and test public-key creation and HD derivation, and `npm run bench:hdkeys` to benchmark those public APIs. Both groups of operations share the addon and its backend selector.

The explicit build places the same release binary in each coin package's `lib/native` directory. Node loads it by default when present. For Bitcoin, set `BITCORE_ECDSA_BACKEND=js` to use the fallback or `native` to require a loadable addon. The coin forks have their own selectors documented below. Select the backend before importing Bitcore. The npm tarballs exclude the local binary, and browser builds use JavaScript. Linux x64 was tested. macOS has linker support but has not been tested. Windows uses the fallback.

The native path accepts high-S signatures for verification. With `randomK`, Bitcore draws each nonce using its existing JavaScript randomness source and passes the candidate to libsecp256k1. Deterministic signing of digests at or above the curve order uses Bitcore's original signer to preserve its nonce behavior. When a caller requests the precise verification error for a rejected signature, the wrapper uses the original point calculation to distinguish an infinite point from other invalid signatures.

The native build and test scripts target Linux and macOS. Signing, converting a private key to a public key, and deriving from a private extended key require OS entropy when the process first initializes the blinded curve context. If entropy is unavailable, the call throws and a later call can retry. This also applies when parsing an extended private key, since Bitcore computes its public key during construction.

The derivation crate handles both standard BIP32 and Bitcore's historical unpadded hardened derivation. For a path such as `m/84'/0'/0'/0/5`, it computes intermediate keys and chain codes in Rust and returns the fields needed to construct the final Bitcore object. The public API still parses paths, checks networks, and serializes extended keys. An older ECDSA-only addon uses JavaScript for derivation.

## Measurements

The benchmark runs both backends through Bitcore's public API in separate Node processes. It alternates execution order across five rounds, warms each operation for at least 250 ms, and measures throughput for at least one second per round. It emits the individual samples, median rates and speedup ratios as JSON. Sixteen hash-derived keys and messages exercise signing, verification with a parsed or serialized key, recovery, and constructing and signing a one-input P2PKH transaction. Compare medians on the same machine.

On Linux x64 with Node 24.22.3, Rust 1.99.1 in release mode, and an Intel Core Ultra 9 275HX, the ECDSA benchmark measured the following medians in operations per second.

| Operation | JavaScript | Native | Speedup |
| --- | ---: | ---: | ---: |
| Sign digest | 2,709 | 55,498 | 20.5× |
| Verify with parsed key | 1,168 | 39,210 | 33.6× |
| Reject invalid signature with parsed key | 1,166 | 37,605 | 32.2× |
| Verify with serialized key | 890 | 30,793 | 34.6× |
| Recover public key | 535 | 28,815 | 53.9× |
| Find recovery factor | 337 | 21,384 | 63.4× |
| Construct and sign P2PKH transaction | 757 | 13,743 | 18.2× |

Median time to require the package was 37.1 ms for JavaScript and 33.7 ms for native. In the earlier ECDSA pilot, native verification with serialized keys reached 3,356 ops/s. The SEC parser now validates and decompresses those keys through libsecp256k1. Public-key recovery also uses this parser to construct the returned Bitcore object.

### Public keys and HD wallet derivation

On the same hardware and Node version, `npm run bench:hdkeys` measured these median public-API rates for the HD pilot before the SEC parser change. The fresh-key benchmark constructs a private key and asks for its public key once. The HD benchmarks start with parsed parent keys, as a wallet would when deriving the next address.

| Operation | JavaScript ops/s | Native ops/s | Speedup |
| --- | ---: | ---: | ---: |
| Fresh public key | 2,685 | 66,481 | 24.8× |
| One normal private child | 2,405 | 23,677 | 9.8× |
| One hardened private child | 2,415 | 25,715 | 10.6× |
| One public child | 1,451 | 3,240 | 2.2× |
| Private receive path `m/84'/0'/0'/0/i` | 491 | 15,386 | 31.3× |
| Watch-only path `m/0/i` | 722 | 3,066 | 4.2× |
| Private receive path plus default address serialization | 488 | 13,696 | 28.1× |

### Bitcoin Schnorr and Taproot

`npm run test:taproot` exercises published vectors, exceptional legacy inputs and signed P2TR spends. `npm run bench:taproot` measures the public API with the same alternating five-round protocol.

| Operation | JavaScript ops/s | Native ops/s | Speedup |
| --- | ---: | ---: | ---: |
| BIP340 sign | 504 | 21,777 | 43.2× |
| BIP340 verify with parsed key | 755 | 39,178 | 51.9× |
| Public Taproot tweak | 1,957 | 42,036 | 21.5× |
| Private Taproot tweak | 3,451 | 89,630 | 26.0× |
| Construct and sign a P2TR transaction | 199 | 5,845 | 29.4× |

Signing preserves Bitcore's historical minimal-integer encoding of the masked secret used in nonce generation. The callback evaluates all 32 possible byte lengths on every call. Verification and key parsing retain Bitcore's historical compatibility with irregular encodings through the JavaScript fallback. This includes some out-of-field coordinates and noncanonical SEC encodings that Bitcoin Core rejects.

### Bitcoin transaction signing and public-key parsing

`npm run bench:transactions` uses eight-input legacy P2PKH transactions. Signing and verification rates count complete sets of eight input signatures.

| Operation | JavaScript ops/s | Native ops/s | Speedup |
| --- | ---: | ---: | ---: |
| Parse compressed SEC public key | 3,720 | 232,202 | 62.4× |
| Parse uncompressed SEC public key | 5,433 | 883,348 | 162.6× |
| Hash eight inputs | 14,013 | 14,434 | 1.03× |
| Sign eight inputs | 327 | 4,559 | 13.9× |
| Verify eight input signatures | 139 | 3,608 | 25.9× |

Both backends skip redundant empty-input copies in the JavaScript sighash serializer. In a separate comparison of that change alone, the original serializer at `41ec965c4` hashed 9,447 sets/s and the revised version hashed 11,225 sets/s (1.19×). This comparison alternated the two implementations in a single process over the same four eight-input fixtures, with five 1 s samples per implementation.

### Wallet operations

After building the workspace's `@bitpay-labs/crypto-wallet-core` TypeScript output, `npm run bench:wallet` runs the public deriver with all coin packages imported in the same process. The receive-key benchmark starts with a serialized extended private key and uses a fresh address index on each call. The address-only benchmark starts with an encoded public key.

| Chain | Receive keys/s, JS → native | Speedup | Addresses from public keys/s, JS → native |
| --- | ---: | ---: | ---: |
| Bitcoin | 799 → 8,099 | 10.1× | 3,637 → 80,641 |
| Bitcoin Cash | 789 → 7,737 | 9.8× | 3,718 → 86,449 |
| Litecoin | 777 → 7,822 | 10.1× | 3,701 → 78,100 |
| Dogecoin | 1,180 → 8,104 | 6.9× | 3,679 → 79,539 |
| Ethereum | 787 → 6,916 | 8.8× | 3,408 → 32,752 |
| XRP | 544 → 5,992 | 11.0× | 133,890 → 126,031 |
| Solana | 282 → 320 | 1.1× | 633,866 → 631,127 |

These measurements predate the native XRP and Solana providers. The [coverage report](COVERAGE.md) has the subsequent benchmarks for each provider.

`bench:wallet-signing` signs complete transfers through ethers, xrpl, and the Solana SDK. `bench:tss` creates a three-party threshold key, signs with two parties, and checks both signers' result against the joint public key. Both benchmarks run the selected backend. For example, `BITCORE_ECDSA_BACKEND=js npm run bench:tss` and `BITCORE_ECDSA_BACKEND=native npm run bench:tss` measure the same session under each backend. TSS timings exclude network transport and include serialization and signature conversion.

Before the account-chain signing changes, Ethereum signed 192 transfers/s under both settings, XRP signed 1,274/1,290 and Solana signed 8,901/9,103 (JS/native). Both benchmark processes ran on the same logical CPU, and signed transaction bytes matched for every chain.

| TSS operation | JS total | Native total | Bitcore message encryption and authentication, JS → native | BitGo SDK round handlers, JS → native |
| --- | ---: | ---: | ---: | ---: |
| 2-of-3 key generation | 1,260 ms | 1,213 ms | 71 → 28 ms | 1,179 → 1,176 ms |
| 2-of-3 signing | 833 ms | 819 ms | 28 → 13 ms | 790 → 791 ms |

Figures are medians of five complete in-process sessions after one warmup. SDK round handlers accounted for about 97% of native session time in both phases. The measured improvement came from Bitcore's existing ECDSA and public-key operations used to authenticate messages. The DKLS protocol runs in the SDK.

### Rebuild scope

The Cargo workspace has separate crates for ECDSA, HD derivation, Bitcoin Taproot, Bitcoin Cash Schnorr, KDFs, Merkle trees, Base58, ECIES, Ed25519, account-chain wallet operations and XRPL family seeds. A single Node adapter exposes them. Cargo rebuilds a changed crate and its dependents. For example, changing the Base58 crate recompiles it and the Node adapter. The Merkle, Ed25519 and KDF crates build independently of ECDSA. The local XRPL derivation build compiled the XRPL key crate and the Node adapter in 0.61 s with dependencies cached.

The following measurements are from the earlier five-component workspace. They used a fresh copy, cached dependency sources and one comment-only edit per component.

| Change | Workspace crates rebuilt | Elapsed |
| --- | --- | ---: |
| Empty target directory | All crates and dependencies | 3.29 s |
| Repeat build | None | 0.02 s |
| HD derivation | HD derivation and Node adapter | 0.44 s |
| ECDSA | ECDSA and Node adapter | 0.36 s |
| Bitcoin Taproot | Taproot and Node adapter | 0.45 s |
| Bitcoin Cash Schnorr | BCH Schnorr and Node adapter | 0.45 s |
| KDF | KDF and Node adapter | 0.40 s |
| Node adapter | Node adapter | 0.32 s |

### Mnemonic seeds and proof of work

`Mnemonic.toSeed` uses RustCrypto PBKDF2-HMAC-SHA512 for BIP39 when the addon is available and each normalized input is at most 4 KiB. Other BIP39 inputs use Node's `crypto.pbkdf2Sync` when available. Dogecoin and Litecoin use RustCrypto scrypt for 80-byte proof-of-work headers and Node's `crypto.scryptSync` for other inputs accepted by `Hash.scrypt`. Both scrypt paths use `N=1024`, `r=1`, and `p=1`. The existing JavaScript implementations cover browsers, FIPS mode, and older runtimes without the relevant native function. Explicit provider-unsupported errors also use the original implementation for fixed-cost scrypt and BIP39. When replaying BIP39, long HMAC keys are hashed once. Node's generic `Deriving bits failed` error is propagated because it does not identify an unsupported provider. The addon clears its copies of mnemonic inputs and seed after it produces the Node buffer.

```sh
npm run test:kdfs
npm run bench:kdfs
```

The benchmark runs public APIs in separate Node workers for the original JavaScript, built-in Node crypto, and Rust paths. It checks BIP39 vectors, valid and invalid proof-of-work fixtures, and that each public method reaches the selected backend. Each sample warms up for 150 ms and measures for at least 350 ms. The table gives medians across five rounds on Linux x64 with Node 24.22.3, OpenSSL 3.5.9, and an Intel Core Ultra 9 275HX.

| Public API | Original ops/s | Node crypto ops/s | Rust addon ops/s |
| --- | ---: | ---: | ---: |
| `Mnemonic.toSeed` | 265 | 1,748 | 1,795 |
| Dogecoin `BlockHeader.validProofOfWork` | 1,032 | 6,039 | 7,176 |
| Litecoin `BlockHeader.validProofOfWork` | 1,012 | 6,012 | 7,144 |

Node crypto delivered most of the speedup and works without a local addon. Rust added about 3% for mnemonic seeds and 19% for both proof-of-work checks on this machine.

### Coin forks

The explicit build installs the addon separately for Bitcoin Cash, Litecoin, and Dogecoin. Each package ships a JavaScript backend for standalone npm installs and browser bundles. Set `BITCORE_BCH_BACKEND`, `BITCORE_LTC_BACKEND`, or `BITCORE_DOGE_BACKEND` before importing the package. Each selector accepts `auto`, `js`, and `native`. An explicit per-coin `native` setting requires a loadable, compatible addon. Without a per-coin setting, `BITCORE_ECDSA_BACKEND=js` selects JavaScript and the default and global `native` settings try the addon with a JavaScript fallback. This lets a Bitcoin-only addon install continue to use the forks.

Bitcoin Cash uses its May 2019 Schnorr protocol, including the existing deterministic nonce domain and the positive Jacobi symbol for the nonce point's Y coordinate. Native operations involving private scalars need OS entropy when first initializing the blinded secp256k1 context. The operation returns an error if entropy is unavailable, and a later operation can retry.

`npm run test:forks` checks the BCH Schnorr fixture, API parity and native dispatch in both package load orders, and standalone fallback when the fork addon is unavailable. `npm run bench:forks` measures each public API in fresh processes with five alternating rounds, 100 ms warmups, and 300 ms sample windows. The private workload derives a five-step BIP44 path. The watch-only workload derives a two-step public path. Both vary indexes between calls to exercise Dogecoin's derivation on cache misses.

The table gives median rates on Linux x64 with Node 24.22.3 and an Intel Core Ultra 9 275HX.

| Fork | Public API | JavaScript ops/s | Native ops/s | Speedup |
| --- | --- | ---: | ---: | ---: |
| Bitcoin Cash | ECDSA sign | 2,655 | 59,503 | 22.4× |
| Bitcoin Cash | ECDSA verify | 1,148 | 40,910 | 35.6× |
| Bitcoin Cash | Create public key | 2,625 | 66,420 | 25.3× |
| Bitcoin Cash | Parse compressed public key | 3,753 | 222,070 | 59.2× |
| Bitcoin Cash | Private path | 464 | 14,746 | 31.8× |
| Bitcoin Cash | Watch-only path | 686 | 13,770 | 20.1× |
| Bitcoin Cash | BCH Schnorr sign | 1,196 | 30,095 | 25.2× |
| Bitcoin Cash | BCH Schnorr verify | 867 | 17,441 | 20.1× |
| Litecoin | ECDSA sign | 2,712 | 59,959 | 22.1× |
| Litecoin | ECDSA verify | 1,170 | 40,753 | 34.8× |
| Litecoin | Create public key | 2,674 | 67,194 | 25.1× |
| Litecoin | Parse compressed public key | 3,777 | 218,773 | 57.9× |
| Litecoin | Private path | 467 | 14,639 | 31.3× |
| Litecoin | Watch-only path | 686 | 13,802 | 20.1× |
| Dogecoin | ECDSA sign | 2,730 | 59,272 | 21.7× |
| Dogecoin | ECDSA verify | 1,161 | 41,098 | 35.4× |
| Dogecoin | Create public key | 2,576 | 70,445 | 27.3× |
| Dogecoin | Parse compressed public key | 3,790 | 218,677 | 57.7× |
| Dogecoin | Private path | 774 | 6,921 | 8.9× |
| Dogecoin | Watch-only path | 684 | 8,541 | 12.5× |

### EVM and XRP wallet providers

The EVM transaction providers share the EVM signing, hashing, and recovery implementation. This covers ETH, ARB, BASE, OP, MATIC, and ARC, their registered ERC-20 providers, and the ETH and MATIC multisig contracts. The providers still use ethers for transaction parsing and encoding and Web3 for contract ABI encoding. Canonical type 0, 1, and 2 transactions use one recovery when a submitted unsigned transaction matches the parsed unsigned bytes. Other recovery and transaction types use the ethers path. EVM address derivation uses Keccak-256 and EIP-55. The EVM, XRP, and legacy SOL message routes retain their existing Ethereum message prefix and count JavaScript string length before UTF-8 encoding.

XRPL retains responsibility for transaction validation, binary encoding, address Base58Check encoding, and verification through the SDK. Unsigned transactions with canonical keys use native low-S DER secp256k1 or Ed25519 signatures over the XRPL signing bytes. This includes drops and issued-currency payments, ticket payments, trust sets, and offers. The full native signing call returns the signed blob without re-encoding it. Multisign handling, unusual key encodings, and payment amounts that still need XRPL normalization use the SDK. Separate optional exports handle signing preimages above 4,096 bytes for secp256k1 or 1,232 bytes for Ed25519. Older addons use the SDK above those sizes. XRP transaction hashing retains the XRPL transaction ID prefix and uppercase SHA-512-half output.

`node native/test-cwc-ledgers.cjs` compares canonical serialized transactions, signatures, hashes, addresses, and errors with both backends after compiling crypto-wallet-core. It checks the XRPL SDK can verify both kinds of signature and confirms each native entry point runs. `node packages/crypto-wallet-core/benchmark/ledgers.js` runs five alternating rounds with 100 ms warmups and 300 ms samples.
