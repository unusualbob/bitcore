# Crypto and arithmetic coverage across Bitcore

## Upstream master versus this branch

This comparison runs `upstream/master`’s normal Node implementation at commit `53f4dcc19` against this branch at commit `cc7ad21a5` with the release addon enabled for BTC, BCH, LTC and DOGE. Wallet core loads the coin libraries from its own checkout in each run. The two revisions have identical npm lockfiles and use the same installed dependency versions. Each checkout uses its own compiled wallet code. The ratios include all changes along the public call path, including JavaScript improvements.

### Operations with native support on upstream

Upstream used Node’s `crypto.createHash` for SHA-256. This branch uses the one-shot `crypto.hash` API on the benchmarked Node version.

| Public operation | Upstream ops/s | Branch ops/s | Branch / upstream | Lowest change | Highest change | Average change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SHA-256 of serialized xpriv text, hex result | 988,482 | 1,403,798 | 1.42× | +28.53% | +53.36% | +41.79% |

### Operations gaining native support on this branch

For these operations, upstream ran the signing, derivation, hashing or encoding algorithm in JavaScript. Some already called native helpers. For example, BIP39 used native HMAC inside a JavaScript PBKDF2 loop, and Base58Check used native SHA-256 for the checksum while JavaScript handled the radix conversion.

| Public operation | Upstream ops/s | Branch ops/s | Branch / upstream | Lowest change | Highest change | Average change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BTC deterministic ECDSA sign and DER encode | 2,999 | 55,289 | 18.434× | +1,710.14% | +1,770.28% | +1,743.47% |
| BTC ECDSA verify with parsed public key | 1,267 | 41,530 | 32.79× | +3,139.61% | +3,227.03% | +3,178.36% |
| BCH Schnorr sign and serialize | 1,262 | 29,628 | 23.474× | +2,204.77% | +2,277.72% | +2,244.32% |
| DOGE scrypt, 80-byte header | 1,006 | 7,979 | 7.928× | +680.70% | +723.71% | +696.74% |
| LTC scrypt, 80-byte header | 1,042 | 7,962 | 7.643× | +645.87% | +701.17% | +667.24% |
| BIP39 mnemonic to seed | 289 | 1,830 | 6.338× | +507.56% | +544.40% | +526.28% |
| TSS ECIES key derivation | 1,368 | 31,593 | 23.095× | +2,186.28% | +2,238.25% | +2,212.56% |
| ETH type-2 transaction signing | 172 | 11,952 | 69.679× | +6,738.66% | +6,911.70% | +6,849.83% |
| Base58Check extended key encode | 91,470 | 1,627,250 | 17.79× | +1,576.75% | +1,761.97% | +1,675.22% |
| Base58Check extended key decode | 134,509 | 1,214,217 | 9.027× | +747.14% | +868.11% | +803.03% |
| EVM sighash, 4,096 bytes | 6,183 | 87,979 | 14.229× | +1,244.82% | +1,433.49% | +1,327.11% |
| EVM sighash, 4,097 bytes | 6,191 | 94,077 | 15.196× | +1,386.98% | +1,441.61% | +1,419.52% |
| Solana receive-key derivation from a serialized xpriv | 335 | 61,176 | 182.654× | +16,428.65% | +18,512.80% | +17,920.86% |
| XRP Ed25519 signing, drops payment | 1,139 | 5,208 | 4.571× | +343.53% | +391.62% | +360.34% |
| XRP Ed25519 signing, issued-currency payment | 1,052 | 4,678 | 4.448× | +333.92% | +359.59% | +344.70% |

Each throughput is the median of ten rounds. The ratio divides the branch median by the upstream median before rounding. Lowest, highest and average change use each round’s percentage change in throughput relative to its baseline. The tests ran on Linux x64, Node 24.22.3, with fresh Node workers, 100 ms warmup and at least 300 ms of measurement per operation. Both revisions returned matching results on every fixture. The SHA-256 row measures a change in how Bitcore calls Node crypto. The ECIES row measures local key derivation within TSS. These offline workloads exclude network and database time.

For a ten-round run, use the benchmark’s `--sample` mode in fresh Node workers and alternate which checkout runs first. Compile crypto-wallet-core in both checkouts, build the release addon on the branch, and set the BTC (`BITCORE_ECDSA_BACKEND`), BCH, LTC and DOGE backend selectors to `native`. A single upstream sample takes `--sample <upstream-root> --upstream`. A branch sample takes `--sample <branch-root>`. The two-checkout command takes `<upstream-root> <branch-root> --upstream` and runs five rounds. [Benchmark and fixtures](bench-native-revisions.cjs)

### General workloads

These offline workloads time complete public API calls. Both columns use the revisions above. The transaction rows construct and sign a three-output transaction with one key for all 32 inputs. The wallet proposal rows call `Key.sign` with 32 distinct input paths, including key derivation and signature collection. SOL, SPL, EVM and XRP signing starts with a prepared transaction. The Merkle row validates the root of an already parsed block.

| Workload | Upstream ms/op | Branch ms/op | Speedup | Lowest change | Highest change | Average change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| BTC transaction, 32 P2PKH inputs | 42.44 | 1.99 | 21.28× | +1,957.2% | +2,600.1% | +2,088.4% |
| BTC transaction, 32 P2WPKH inputs | 40.05 | 1.97 | 20.32× | +1,910.3% | +2,460.4% | +2,000.4% |
| BTC transaction, 32 Taproot inputs | 156.62 | 4.67 | 33.55× | +3,226.1% | +4,136.4% | +3,357.9% |
| BCH transaction, 32 fork-ID P2PKH inputs | 43.24 | 2.05 | 21.10× | +1,932.7% | +2,445.8% | +2,047.2% |
| DOGE transaction, 32 P2PKH inputs | 43.16 | 1.95 | 22.13× | +2,080.7% | +2,293.7% | +2,142.3% |
| LTC transaction, 32 P2WPKH inputs | 41.83 | 2.00 | 20.87× | +1,930.4% | +2,080.2% | +1,996.1% |
| BTC wallet proposal, 32 P2PKH inputs and keys | 44.26 | 2.96 | 14.94× | +1,351.9% | +1,413.3% | +1,384.1% |
| BTC wallet proposal, 32 P2WPKH inputs and keys | 42.02 | 2.96 | 14.22× | +1,282.1% | +1,372.0% | +1,317.6% |
| BTC wallet proposal, 32 Taproot inputs and keys | 3,640.80 | 6.36 | 572.75× | +55,730.6% | +58,321.9% | +57,002.5% |
| SOL transfer, sign | 0.242 | 0.039 | 6.26× | +290.2% | +632.9% | +495.8% |
| SPL token transfer, sign | 0.220 | 0.052 | 4.26× | +240.9% | +381.6% | +319.6% |
| TSS ECIES encrypt, 256 bytes (fixture IV) | 0.760 | 0.039 | 19.55× | +1,816.7% | +1,917.2% | +1,854.1% |
| TSS ECIES decrypt, 256 bytes | 0.983 | 0.038 | 25.98× | +2,433.6% | +2,517.8% | +2,485.8% |
| Arbitrum ERC-20 transfer, sign | 5.88 | 0.105 | 56.14× | +5,376.5% | +5,648.2% | +5,507.8% |
| ETH multisig contract call, sign | 5.68 | 0.103 | 55.08× | +5,334.3% | +5,534.6% | +5,402.6% |
| XRP issued-currency payment, secp256k1 sign | 0.931 | 0.211 | 4.40× | +320.3% | +353.4% | +337.9% |
| BTC block 357238, validate Merkle root (369 transactions) | 2.04 | 1.07 | 1.90× | +80.3% | +92.4% | +88.3% |

Times are median milliseconds per operation across ten paired rounds on Linux x64, Node 24.22.3 (Core Ultra 9 275HX). Each pair used fresh processes and alternated which revision ran first. Each workload warmed up for at least 100 ms and ran for at least 300 ms per sample, completing the last operation in each window. Speedup divides upstream median time by branch median time. The last three columns report changes in throughput across the paired rounds. Output checks ran outside the timing window. For randomized Taproot signatures, the harness verified each sampled signature against its spent output and compared the transaction or ordered signing digests across revisions.

The 32-key Taproot proposal shows the largest gain. Upstream tries each key against every input. The branch matches tweaked keys to spent output scripts before signing, so it avoids most of those attempts as well as accelerating the cryptography.

To reproduce with the same Node version, compile crypto-wallet-core and bitcore-wallet-client in both checkouts, build the release addon in the branch checkout, then run `node native/bench-workloads.cjs <upstream-root> <branch-root>` from the branch. The runner prints the per-round times and summary statistics. [Workload benchmark](bench-workloads.cjs)

## Chain coverage

The wallet registry currently contains 12 chains. The transaction registry has 21 routes, including six ERC-20 routes, ETH and MATIC multisig, and SOLSPL. Bitcoin Lightning has a separate RPC provider. These registries are the starting point for a new chain or asset review.

| Chain or route | Local operations and execution path |
| --- | --- |
| ETH, MATIC, ARB, BASE, OP, ARC | BIP32 and secp256k1 key generation, Keccak-256, EIP-55 address creation and validation, recoverable ECDSA signing and sender recovery. Each chain uses its configured chain ID. The wallet calls the same transaction provider for the shared cryptography. |
| ETHERC20, MATICERC20, ARBERC20, BASEERC20, OPERC20, ARCERC20, ETHMULTISIG, MATICMULTISIG | Web3 encodes token and contract calls. The resulting transaction uses the corresponding EVM signing and hashing path. |
| XRP | BIP32, XRPL family-seed derivation, secp256k1 and Ed25519 signing, account-ID hashing and SHA-512Half. XRPL controls transaction encoding and validation. |
| SOL, SOLSPL | SLIP-0010 child derivation, Ed25519 public-key expansion and transaction signing, address encoding and associated token account derivation. Solana Kit controls message encoding and signer requirements. |
| BTC | ECDSA, public-key recovery, BIP32, BIP340 Schnorr, Taproot tweaks, legacy/witness/Taproot sighashes, double SHA-256 and Merkle trees. |
| BCH | ECDSA, BIP32, the 2019 BCH Schnorr algorithm, fork-ID sighash, cashaddr, double SHA-256 and Merkle trees. |
| LTC, DOGE | ECDSA, BIP32, legacy and witness signing paths where exposed, Merkle trees and fixed-parameter scrypt proof of work. Dogecoin preserves its HD key cache. |
| LNBTC | LND owns wallet and channel operations. Its client also parses BOLT11 responses and recovers invoice signers locally. |

The message API has its own compatibility rules. BTC, BCH, DOGE and LTC use the existing Bitcoin message format through the wallet proxy. SOL and XRP inherit the Ethereum-compatible message implementation. Solana transactions still use Ed25519, and XRP transactions still use the signing format selected by XRPL.

In a separate offline regression run on Linux x64 with Node 24.22.3, the branch’s JavaScript and native backends each passed 19,161 tests with 16 pending. The suites cover the four coin libraries, three P2P packages, mnemonic, CWC, TSS, wallet packages, and offline node, RPC and CLI tests. Separate parity scripts exercise native dispatch, signed bytes, SDK fallback and wallet ordering. Earlier in the migration, Browserify produced full bundles for all four coin libraries. The final parity run also tested the browser codec bundles. Live daemon and MongoDB integrations, a real FIPS runtime and the client wallet tests needing the missing bcrypt binding remain outside this comparison. [RPC measurements with stubbed providers](RPC-COVERAGE.md)

## Shared wallet and service operations

* Mnemonic-to-seed conversion uses PBKDF2-HMAC-SHA512. Desktop and server callers can use the addon or Node crypto. Wallet-password encryption uses a separate PBKDF2-HMAC-SHA256 operation. AES encryption and authenticated decryption already have Node crypto implementations.
* TSS message authentication uses ECDSA. Point-to-point message encryption uses a dedicated ECIES crate for the raw shared x coordinate and compressed public keys, followed by Node HKDF-SHA256, AES-CBC and HMAC. Threshold key generation and signing rounds use the DKLS WebAssembly modules loaded by the BitGo SDK.
* The client signs API requests with a double-SHA256 digest and compact ECDSA signature. The node and wallet service have separate verification APIs with their own high-S and signature-import behavior.
* Wallet services and the CLI call the wallet or chain libraries for derivation, signing and payment authentication. Amount formatting and fee calculations operate on JavaScript numbers, native V8 BigInts and caller-owned objects. Consensus script execution and transaction parsing also preserve their public objects, error behavior and wire formats.

## Measuring the public APIs

Run the benchmarks from the checkout root using the Node version in `.node-version`. Build the release addon and compile the wallet TypeScript before measuring. The chain coverage test derives receive and change keys on two networks for every entry in `Constants.CHAINS`, checks key import, compares address validation and exercises signed messages with both backends.

```sh
node native/build-node.cjs
node node_modules/typescript/bin/tsc -p packages/crypto-wallet-core
node native/test-chain-coverage.cjs
node native/test-ecies.cjs
node packages/crypto-wallet-core/benchmark/validation.js
node packages/bitcore-tss/benchmark/ecies.js
```

Each performance decision applies to its measured workload. A sender recovery benchmark measures local computation. A full RPC call also includes network, database or daemon latency. Similarly, faster ECIES improves the transport portion of TSS, while the protocol rounds retain their own cost.

### EVM and XRP transaction workloads

The SDK wire-format and error-parity corpus runs with `node native/test-cwc-ledgers.cjs` after compilation.

The corpus covers all six EVM chains, their token routes, and both multisig providers. It compares transaction types 0, 1, and 2, malformed signature scalars and legacy V encodings, ECDSA message digests at and above the curve order, and Unicode and long messages. The XRP corpus compares the signed blob, signature, hash, and validation errors for secp256k1 and Ed25519. It checks issued amounts, tickets, trust sets, offers, multisign rejection, unusual keys, and provider overrides. The larger signing fixtures exercise both optional exports and confirm SDK fallback when those exports are missing. XRPL remains responsible for validation, codecs, and signature verification.

## Solana and SPL

Solana receive-key derivation uses RustCrypto HMAC-SHA512 for the SLIP-0010 path and dalek for Ed25519 public-key expansion. The same Ed25519 implementation signs SOL and SPL transaction messages, including partial signing, and signs text for `bitcore-client`’s `Wallet.solSignMessage`. The transaction path looks up the seed-derived address in the decoded signer map. Solana Kit enforces a complete signature set for full signing and encodes the wire transaction. The SDK and crypto-rpc share the associated-token PDA path through `SolanaProgram.Token.findAssociatedTokenPda`. Account existence and balances are queried through Solana RPC.

Serialized root derivation decodes the extended private key once, validates the scalar, and passes the key and chain code to SLIP-0010. SOL signing and SPL ATA derivation reuse Bitcore's Base58 codecs. `Wallet.solSignMessage` uses the optional large-message Ed25519 export for messages above 1,232 bytes.

```sh
cargo test --locked --manifest-path native/Cargo.toml -p bitcore-ed25519
node native/test-sol.cjs
node packages/crypto-wallet-core/benchmark/sol.js
```

The [RPC and node measurements](RPC-COVERAGE.md) cover checksum formatting during chain sync, EVM transaction decoding, XRP wallet signing, Solana signing and token accounts, Lightning invoice processing and calls delegated to chain daemons.

## Multi-input signing and block validation

`Transaction.sign` and `getSignatures` reuse transaction-wide hashes during one synchronous operation on the built-in input and output types. This covers witness v0, BCH fork ID, and Taproot. Legacy `SIGHASH_ALL` reuses a transaction template and inserts each input's script before hashing. Standalone sighashes read the current transaction. Custom serialization or signature methods use the original computation.

Blocks with 8 to 65,536 ordinary leaves batch Merkle parent hashing through Rust. The full-block Merkle-root benchmark serializes and hashes 1,001 transactions cloned from one signed fixture with different locktimes. Compact difficulty decoding uses one BN shift per target and preserves the historical handling of exponents below three.

BCH zero-confirmation escrow sorts the public keys, pads the leaf set and uses HASH160.

The transaction and block parsers continue to construct the existing JavaScript objects and handle witness, CashTokens and AuxPoW wire formats. Script interpreters retain opcode, stack and error semantics and call the optimized signature APIs.

### Partial Merkle proofs, block roots and escrow

BTC, BCH, DOGE and LTC submit ordinary partial proofs with 8 to 65,536 hashes in one Rust call. Validation reconstructs the root. For match queries, Rust returns indices into the supplied hash list. JavaScript uses those indices to recover the original hash strings with their case preserved. JavaScript handles malformed proofs and custom traversal or hashing methods. Full-block calls that only need the root reduce the leaves in place in Rust. The public tree API still returns all levels.

BCH batches HASH160 for escrow roots with 8 to 65,536 eligible leaves or keys. JavaScript applies the existing public-key sorting and SEC parsing rules. The Rust tree pads public-key leaves with HASH160 of the empty buffer. For prehashed inputs, it hashes an unpaired node on its own.

Block header and transaction IDs use Rust SHA256d for eligible preimages up to 512 bytes. HASH160 uses Rust up to 128 bytes. Legacy sighash and larger standalone preimages use OpenSSL. FIPS mode, overridden hash functions and ineligible buffers use the existing fallback.

`native/check-crypto.cjs` discovers `test-utxo-validation.cjs`. The test covers native dispatch, fallback parity, malformed proofs, mixed-case matches, odd escrow trees, and full roots around the batch threshold.

## Wallet imports, authentication and shared arithmetic

Wallet-client uses OpenSSL for PBKDF2 password derivation and reuses decrypted data within a single operation. Legacy decryption can fall back to SJCL. Bitcoin’s `Point.liftX` uses native SEC parsing and a Jacobi symbol to preserve the coordinate’s BN prototype.

The [wallet KDF](bench-wallet-kdfs.cjs), [client authentication](../packages/bitcore-client/benchmark/auth-crypto.mjs), [message signing](bench-random-nonce.cjs), [encoding](bench-encoding.cjs) and [public point](../packages/bitcore-lib/benchmark/point.js) benchmarks record their respective fixtures and comparison modes.

### BIP32 watch-only address import

On all 11 BIP32 chains, `Wallet.syncAddresses` parses the account xpub once for eligible range imports with `addressIndex > 1`. For BTC, BCH, LTC, XRP, and the six EVM chains, it reuses the receive and change parents and requests up to 256 consecutive public children per native call when the corresponding library's addon offers the method. Otherwise it derives under the same parent keys through the library. DOGE retains its full-path derivation calls through its own backend selector so HD key-cache lookups, writes, and recency updates occur in order. Its range path saves repeated xpub parsing. Each chain uses its existing address formatter. SOL cannot derive wallet addresses from an xpub. [Wallet sync](../packages/bitcore-client/src/wallet.ts), [range derivation](../packages/crypto-wallet-core/src/derivation/address-range.ts).

The client preserves receive/change order, saved index zero, signed request bodies, and 100-address pages. Overrides of the wallet method, SDK method, or built-in registry and HD derivation hooks defer to the original per-address call path. That path also handles unsupported inputs and rare native BIP32 tweak failures. The harness exercises the actual wallet and import methods and compares requests, including signatures, URLs, and order. It checks mainnet and testnet fixtures, fork-native dispatch, JS and mixed backend selection, fallback encoders, and DOGE cache traces with and without eviction. Transport and the one-second cooldown after the first page are stubbed. The watch-only fixture stubs bcrypt and fails if it is called. [Address-import harness](bench-wallet-addresses.cjs).

Build the addon and the crypto-wallet-core and bitcore-client TypeScript outputs to run `node native/bench-wallet-addresses.cjs --bench`. Run without `--bench` for parity checks, or set `BITCORE_ECDSA_BACKEND=js` with the fork selectors unset to exercise the JS-only path. The script accepts an optional absolute release `.node` path for the Bitcoin addon. Fork tests use their installed addons and selectors.

### Wallet scan, proposal signing and request authentication

* BWS recovery still probes the explorer sequentially and rewinds at the inactive gap. During a power scan it reuses each copayer’s parsed public branch key while reconstructing skipped BTC, BCH and LTC addresses. The address manager still supplies the paths and their order. The parity corpus compares stored records, receive/change order, rewind indices, reprocessing flags, overrides and error propagation. [Recovery scan](../packages/bitcore-wallet-service/src/lib/server.ts) · [Benchmark](bench-bws-scan.cjs) · [Parity checks](test-bws-scan.cjs)
* [Wallet-client `Key.sign`](../packages/bitcore-wallet-client/src/lib/key.ts) deduplicates derivation by input path and shares the existing transaction sighash cache across multiple keys. Key derivation retains its per-path calls. For canonical BTC Taproot inputs, the native path matches each tweaked key to the spent output scripts and calls the existing signer and verifier for the matching inputs. Custom signing or randomness hooks and unsupported scripts use the per-key signer. [The wallet signature harness](test-wallet-signatures.cjs) verifies duplicates, ordering, script matching independently of path labels, external outputs, and fallback behavior.

* [Node verification](../packages/bitcore-node/src/utils/auth.ts) and [BWS verification](../packages/bitcore-wallet-service/src/lib/common/utils.ts) use the `secp256k1` v4 package, which loaded its compiled binding on the benchmark host.

## UTXO ingestion with MongoDB mocked

`bench-utxo-ingestion.cjs` exercises compiled `bitcore-node` models through `processBlock`, `getBlockOp`, and `batchImport`. The benchmark also measures transaction and mint streams on the original Bitcoin block fixture. It uses in-process collection stubs with empty reads and no-op writes and intercepts MongoDB connection calls. These measurements cover local ingestion work. A deployed node also spends time on real database reads, writes, and indexes.

While testing the fork import path, we found that copying the parent chain's pre-fork transaction records left the transaction stream open. The import now closes the stream after the copy. A [model regression test](../packages/bitcore-node/test/unit/models/utxoSerialization.test.ts) checks that it finishes and preserves the parent's stored transaction size.

Point the benchmark at compiled build directories containing `src/models/block.js`. With no path it uses `packages/bitcore-node/build`. With two paths it compares the first build against the second. Both the default build and the paired baseline and final builds were smoke-tested with Node 24.22.3.

```sh
node native/bench-utxo-ingestion.cjs --smoke
node --expose-gc native/bench-utxo-ingestion.cjs path/to/baseline/build path/to/current/build
```

When measuring detached builds outside a checkout on Linux or macOS, point their bare imports at the workspace's installed dependencies.

```sh
NODE_PATH="$PWD/packages/bitcore-node/node_modules:$PWD/node_modules" \
  node --expose-gc native/bench-utxo-ingestion.cjs path/to/baseline/build path/to/current/build
```
