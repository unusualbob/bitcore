# Crypto and arithmetic coverage across Bitcore

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

On Linux x64 with Node 24.22.3, 20 offline suites passed against commit `195c45bee` and the updated tree. The baseline had 19,154 passing and 16 pending. Forced JavaScript and forced ABI 3 each had 19,161 passing and the same 16 pending. Every baseline test kept its outcome, and all seven new package tests passed in both modes. The suites cover the four coin libraries, three P2P packages, mnemonic, CWC, TSS, wallet packages, and offline node, RPC and CLI tests. Separate parity scripts exercise native dispatch, signed bytes, SDK fallback and wallet ordering. Browserify produced bundles for all four coin libraries. Live daemon and MongoDB integrations, a real FIPS runtime and the client wallet tests needing the missing bcrypt binding remain outside this comparison. [RPC measurements with stubbed providers](RPC-COVERAGE.md)

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

On Linux x64 with Node 24.22.3 and a Core Ultra 9 275HX, the five-sample median throughputs below measure the complete public operation. ECIES used 256-byte messages. The EVM validation fixtures rotate through all six chains.

| Operation | Existing ops/s | Native ops/s | Speedup |
| --- | ---: | ---: | ---: |
| Validate a mixed-case EIP-55 address | 157,334 | 2,071,651 | 13.2× |
| Format an EIP-55 address | 165,659 | 1,196,806 | 7.2× |
| Validate a lowercase EVM address | 3,935,343 | 5,227,135 | 1.3× |
| ECIES derive encryption and authentication keys | 1,231 | 31,287 | 25.4× |
| ECIES encrypt | 1,217 | 24,588 | 20.2× |
| ECIES decrypt | 1,002 | 25,857 | 25.8× |

Each performance decision applies to its measured workload. A sender recovery benchmark measures local computation. A full RPC call also includes network, database or daemon latency. Similarly, faster ECIES improves the transport portion of TSS, while the protocol rounds retain their own cost.

### EVM and XRP transaction workloads

After compilation, run `node native/test-cwc-ledgers.cjs` for SDK wire and error parity and `node packages/crypto-wallet-core/benchmark/ledgers.js` for throughput. The table uses Node 24.22.3 on Linux x64 and a Core Ultra 9 275HX. Each backend ran five alternating samples per operation with a 100 ms warmup and a 300 ms measurement window.

| Operation | Existing ops/s | Native ops/s | Speedup |
| --- | ---: | ---: | ---: |
| Sign ETH type-2 transfer | 161 | 9,929 | 61.81× |
| Sign Arbitrum ERC-20 transfer | 156 | 8,282 | 53.08× |
| Sign ETH multisig contract call | 159 | 8,424 | 52.94× |
| Apply an ETH signature | 158 | 14,213 | 89.99× |
| Hash a signed ETH transaction | 18,625 | 20,450 | 1.10× |
| Hash an unsigned ETH transaction | 188,848 | 596,119 | 3.16× |
| Sign an Ethereum-format message | 1,714 | 20,026 | 11.68× |
| Derive an EVM address from a public key | 6,368 | 114,906 | 18.04× |
| Sign XRP drops payment with secp256k1 | 870 | 4,263 | 4.90× |
| Sign XRP drops payment with Ed25519 | 837 | 4,128 | 4.93× |
| Sign XRP issued-currency payment with secp256k1 | 794 | 3,505 | 4.42× |
| Sign XRP issued-currency payment with Ed25519 | 768 | 3,582 | 4.67× |
| Sign XRP issued-currency payment with a 4,200-byte memo (secp256k1) | 7.66 | 11.94 | 1.56× |
| Sign XRP issued-currency payment with a 1,500-byte memo (Ed25519) | 52.93 | 81.02 | 1.53× |
| Derive an XRP address from a public key | 104,991 | 173,436 | 1.65× |

The XRP signing rows measure `Transactions.sign` from unsigned transaction bytes through signed blob encoding. The large-memo fixtures exercise offline signing above each binding's original size limit.

An isolated Rust SHA-512-half binding achieved 796,527 XRP hashes per second versus 923,089 with Node crypto, about 0.86×. The public transaction-hash method retains Node's SHA-512 implementation. Native secp256k1 transaction signing computes SHA-512-half inside the signing call.

The public EVM sighash benchmark includes hex decoding and digest formatting. On the same Node 24 Linux host, the median of five alternating rounds at 4,097 bytes was 95,426 hashes/s with Rust and 6,049 with ethers (15.8×). At 64 KiB it was 6,580 versus 389 (16.9×), and at 1 MiB it was 417 versus 24 (17.4×). The [benchmark](../packages/crypto-wallet-core/benchmark/large-keccak.js) exercises both sides of the former 4 KiB cutoff.

The corpus covers all six EVM chains, their token routes, and both multisig providers. It compares transaction types 0, 1, and 2, malformed signature scalars and legacy V encodings, ECDSA nonce inputs at and above the curve order, and Unicode and long messages. The XRP corpus compares the signed blob, signature, hash, and validation errors for secp256k1 and Ed25519. It checks issued amounts, tickets, trust sets, offers, multisign rejection, unusual keys, and provider overrides. The larger signing fixtures exercise both optional exports and confirm SDK fallback when those exports are missing. XRPL remains responsible for validation, codecs, and signature verification.

## Solana and SPL

Solana receive-key derivation uses RustCrypto HMAC-SHA512 for the SLIP-0010 path and dalek for Ed25519 public-key expansion. The same Ed25519 implementation signs SOL and SPL transaction messages, including partial signing, and powers the SDK text-message signer. The transaction path looks up the seed-derived address in the decoded signer map. Solana Kit enforces a complete signature set for full signing and encodes the wire transaction. The SDK and crypto-rpc share the associated-token PDA path through `SolanaProgram.Token.findAssociatedTokenPda`. Account existence and balances are queried through Solana RPC.

The existing Ed25519 public-key path uses TweetNaCl. The existing SLIP-0010 HMAC uses Node-backed `create-hmac`. Existing message signing, transaction signing and PDA hashing use Solana Kit on Node 24.22.3's OpenSSL 3.5.9-backed WebCrypto. The medians below use five interleaved rounds on the same Linux x64 Core Ultra 9 275HX.

| Solana operation | Existing ops/s | Native ops/s | Speedup |
| --- | ---: | ---: | ---: |
| Four-step SLIP-0010 child path | 94,754 | 247,553 | 2.61× |
| Ed25519 public key from seed | 275 | 82,211 | 298× |
| Complete receive-key derivation | 216 | 14,650 | 67.9× |
| Sign a 200-byte message | 5,097 | 20,897 | 4.10× |
| Sign a SOL transfer | 4,214 | 16,080 | 3.82× |
| Sign an SPL transfer | 3,841 | 12,616 | 3.28× |
| Derive an associated token PDA | 4,881 | 11,798 | 2.42× |

Serialized root derivation decodes the extended private key once, validates the scalar, and passes the key and chain code to SLIP-0010. SOL signing and SPL ATA derivation reuse Bitcore's Base58 codecs. Message signing uses the optional large-message Ed25519 export above 1,232 bytes.

The incremental comparison below uses the same native addon for both implementations on Node 24.20.0. Each row shows medians from five alternating rounds pinned to one CPU. The receive-key baseline materializes an `HDPrivateKey` before derivation. The 8 KiB baseline uses Solana Kit's signer.

| Solana operation | Previous native path ops/s | Updated native path ops/s | Speedup |
| --- | ---: | ---: | ---: |
| Complete receive-key derivation | 10,032 | 25,415 | 2.53× |
| Sign a 200-byte message | 11,069 | 17,895 | 1.62× |
| Sign an 8 KiB message | 4,300 | 10,982 | 2.55× |
| Sign a SOL transfer | 10,050 | 11,421 | 1.14× |
| Sign an SPL transfer | 10,282 | 11,889 | 1.16× |
| Derive an associated token PDA | 11,162 | 86,488 | 7.75× |

The direct Node OpenSSL alternatives measured 22,336 public keys per second and 16,759 message signatures per second, including private-key import in each operation. With the verification key preloaded and a valid 200-byte message, TweetNaCl verified about 145 signatures per second, Node WebCrypto 10,979, Node OpenSSL 16,731, and dalek strict verification 27,638. Solana Kit exposes Ed25519 verification directly. The wallet message proxy's `SolMessage` uses its existing Ethereum-compatible format.

```sh
cargo test --locked --manifest-path native/Cargo.toml -p bitcore-ed25519
node native/test-sol.cjs
node packages/crypto-wallet-core/benchmark/sol.js
```

The [RPC and node measurements](RPC-COVERAGE.md) cover checksum formatting during chain sync, EVM transaction decoding, XRP wallet signing, Solana signing and token accounts, Lightning invoice processing and calls delegated to chain daemons.

## Multi-input signing and block validation

`Transaction.sign` and `getSignatures` reuse transaction-wide hashes during one synchronous operation on the built-in input and output types. This covers witness v0, BCH fork ID, and Taproot. Legacy `SIGHASH_ALL` reuses a transaction template and inserts each input's script before hashing. Standalone sighashes read the current transaction. Custom serialization or signature methods use the original computation.

Blocks with 8 to 65,536 ordinary leaves batch Merkle parent hashing through Rust. The full block measurement includes transaction serialization and hashing and uses 1,001 synthetic signed transactions. Compact difficulty decoding uses one BN shift per target and preserves the historical handling of exponents below three.

BCH zero-confirmation escrow builds a different tree. It sorts the public keys, pads the leaf set and uses HASH160. Building a 16-participant escrow redeem script measured 643 scripts/s with the JavaScript backend and 5,204 scripts/s with native SEC public-key parsing in a 300 ms sample per backend. The fork benchmark checks that this script builder dispatches to the native parser.

`npm run bench:utxo` uses the same native curve backend in both modes and alternates five before and after samples. The signing rates include constructing, signing, verifying and applying the signatures for a 32-input transaction with three outputs. These medians use Node 24.22.3 on Linux x64 with an Intel Core Ultra 9 275HX.

| Public operation | Before ops/s | After ops/s | Speedup |
| --- | ---: | ---: | ---: |
| BTC legacy signing | 207 | 362 | 1.75× |
| BTC SegWit signing | 288 | 365 | 1.27× |
| BTC Taproot signing | 108 | 160 | 1.48× |
| BCH fork-ID signing | 220 | 376 | 1.71× |
| DOGE legacy signing | 193 | 387 | 2.01× |
| LTC SegWit signing | 279 | 377 | 1.35× |
| BTC full-block Merkle root validation | 166 | 214 | 1.29× |
| BTC compact target decode and bit-length query | 137,529 | 26,245,067 | 190.8× |

The transaction and block parsers continue to construct the existing JavaScript objects and handle witness, CashTokens and AuxPoW wire formats. Script interpreters retain opcode, stack and error semantics and call the optimized signature APIs.

### Partial Merkle proofs, block roots and escrow

BTC, BCH, DOGE and LTC submit ordinary partial proofs with 8 to 65,536 hashes in one Rust call. Validation reconstructs the root. Match queries traverse the same proof and return indices into the original strings, preserving their case. JavaScript handles malformed proofs and custom traversal or hashing methods. Full-block calls that only need the root reduce the leaves in place in Rust. The public tree API still returns all levels.

BCH batches HASH160 for escrow roots with at least eight leaves or keys. JavaScript applies the existing public-key sorting and SEC parsing rules. The Rust tree pads public-key leaves with HASH160 of the empty buffer. For prehashed inputs, it hashes an unpaired node on its own.

Block header and transaction IDs use Rust SHA256d for eligible preimages up to 512 bytes. HASH160 uses Rust up to 128 bytes. Legacy sighash and larger standalone preimages use OpenSSL. FIPS mode, overridden hash functions and ineligible buffers use the existing fallback.

`node native/bench-utxo-validation.cjs` reports the median of five alternating samples. Each comparison toggles the relevant native exports and keeps the same curve backend. The timings include eligibility checks and buffer packing. The following results use Node 24.20.0 on an Intel Core Ultra 9 275HX. Partial-proof fixtures ranged from 19 to 501 proof hashes.

| Public operation | Speedup |
| --- | ---: |
| BTC partial Merkle root validation | 3.46–4.82× |
| BTC partial Merkle match extraction and lookup | 4.74–7.01× |
| BTC full-block root validation, 1,001 transactions | 1.04× |
| BCH escrow redeem script, 16 and 64 keys | 1.18× and 1.13× |
| BCH escrow root, 33 prehashed leaves | 2.91× |
| BTC proof of work with a cold header ID | 1.33× |
| BTC parse a signed two-input transaction and compute its ID | 1.13× |
| BCH public key to address | 1.13× |
| BCH script-hash output, 25- and 128-byte redeem scripts | 1.42× and 1.21× |

Four-key escrow measured 0.99× and stays on its existing tree path. The uncapped digest prototype measured 0.98–1.04× on 512- to 8,192-byte scripts. A standalone 32-input transaction ID also measured about flat. A BigInt proof-of-work comparison prototype measured 1.62× with a cached header ID and 1.07× with a cold header ID, so the BN comparison stays in place. On Node 20.20.2, cold proof of work measured 1.33×, small transaction ID computation 1.17×, and the two short script-hash cases 1.45× and 1.17×.

`native/check-crypto.cjs` discovers `test-utxo-validation.cjs`. The test covers native dispatch, fallback parity, malformed proofs, mixed-case matches, odd escrow trees, and full roots around the batch threshold.

## Wallet imports, authentication and shared arithmetic

The rows below compare each public operation with its previous implementation on Node 24.22.3. The Bitcoin-family message rows enable the previous native recovery path in both measurements, isolating the gain from moving randomized signing into libsecp256k1. JavaScript still draws the nonce.

| Workload | Measured improvement | Implementation |
| --- | ---: | --- |
| Bitcore Client request signing | 21.3× | Rust addon replaces the installed elliptic fallback. Node and BWS authentication already load compiled secp256k1. |
| BTC/BCH/LTC/DOGE wallet message signing | 4.8–4.9× | One candidate nonce per native signing call, including retries |
| Canonical public point validation | 39–52× | Curve equation using secp256k1's cofactor of one |
| Construct a point from its x coordinate | 21–26× | Existing Rust SEC parser |
| BTC `Point.liftX` | 4.43× | Native SEC parser and a Jacobi symbol |
| BCH square test on a point | 22–23× | Jacobi symbol using V8 BigInt |
| Base58 decode, 25 bytes | 3.02× | Batched radix conversion in JavaScript |
| Extended-key Base58Check encode / decode | 1.61× / 2.25× | Batched radix conversion and Node hashing |
| HMAC-SHA256 / HMAC-SHA512 | 1.42× / 1.94× | Node crypto |
| Bitcoin Core wallet import KDF, 200,000 rounds | 5.3–5.7× | Repeated SHA-512 in Rust |
| BIP38 scrypt | 1,133 ms → 170 ms | Node/OpenSSL. Progress callbacks use the original implementation. |

Wallet password PBKDF2 at 600,000 iterations measured 52.13 ms in OpenSSL and 45.47 ms in a standalone Rust release on one core, and 49.12 versus 47.87 ms on another. The wallet keeps OpenSSL and reuses decrypted data within a single operation. Creating Bitcoin credentials now takes two password derivations, down from four. Solana credentials take three, down from six. BIP37 Bloom hashing measured about three million inserts or hits per second with the existing JavaScript implementation. Public BN and elliptic methods preserve their object and prototype contracts.

Bitcoin's `Point.liftX` reuses native SEC parsing and uses a Jacobi symbol to preserve the returned coordinate's BN prototype. Its median throughput rose from 8,469 to 37,474 calls/s over five alternating samples per backend on Node 24.22.3. A trial that intercepted `Point.getG().mul` on the shared elliptic curve measured 14–18× higher throughput on Node 24.20.0. It also intercepted multiplication in other consumers of that curve. Generator and arbitrary-point multiplication continue to use elliptic through the public Point API. Public-key creation, BIP32 derivation, signing, and Taproot tweaks have dedicated native entry points.

The [wallet KDF](bench-wallet-kdfs.cjs), [client authentication](../packages/bitcore-client/benchmark/auth-crypto.mjs), [message signing](bench-random-nonce.cjs), [encoding](bench-encoding.cjs) and [public point](../packages/bitcore-lib/benchmark/point.js) benchmarks record their respective fixtures and comparison modes.

The [Base58 benchmark](bench-base58.cjs) compares the Rust codec against Bitcore's optimized JavaScript codec. On Node 24.22.3, five samples on the same logical CPU measured these public Base58Check operations. The four coin packages share the Rust crate.

| Payload | Encode ops/s, JS → Rust | Decode ops/s, JS → Rust |
| --- | ---: | ---: |
| Address | 473,250 → 2,433,317 (5.14×) | 568,152 → 1,411,944 (2.49×) |
| WIF private key | 369,224 → 2,223,880 (6.02×) | 531,303 → 1,388,323 (2.61×) |
| Extended key | 174,736 → 1,372,954 (7.86×) | 346,743 → 1,156,268 (3.33×) |

### BIP32 watch-only address import

`Wallet.syncAddresses` parses the account xpub once across all 11 BIP32 chains. For BTC, BCH, LTC, XRP, and the six EVM chains, it reuses the receive and change parents and requests up to 256 consecutive public children per native call when the corresponding library's addon offers the method. Otherwise it derives under the same parent keys through the library. DOGE retains its full-path derivation calls through its own backend selector so HD key-cache lookups, writes, and recency updates occur in order. Its range path saves repeated xpub parsing. Each chain uses its existing address formatter. SOL cannot derive wallet addresses from an xpub. [Wallet sync](../packages/bitcore-client/src/wallet.ts), [range derivation](../packages/crypto-wallet-core/src/derivation/address-range.ts).

The client preserves receive/change order, saved index zero, signed request bodies, and 100-address pages. Overrides of the wallet method, SDK method, or built-in registry and HD derivation hooks defer to the original per-address call path. That path also handles unsupported inputs and rare native BIP32 tweak failures. The harness exercises the actual wallet and import methods and compares requests, including signatures, URLs, and order. It checks mainnet and testnet fixtures, fork-native dispatch, JS and mixed backend selection, fallback encoders, and DOGE cache traces with and without eviction. Transport and the one-second cooldown after the first page are stubbed. Unused bcrypt functions are stubbed because the workspace lacks the binary. [Address-import harness](bench-wallet-addresses.cjs).

Linux x64, Core Ultra 9 275HX, Node 24.20.0 and release Rust 1.99.1. Each cell reports the median milliseconds per signed 100-address import, existing scalar → range, using five alternating samples per mode after 100 ms warmups and at least 175 ms per sample. Both sides use the same backend and encoders. DOGE is warm except in the labeled row.

| Chain | Native enabled, ms | JavaScript only, ms |
| --- | ---: | ---: |
| BTC | 9.582 → 3.359 | 102.746 → 47.340 |
| BCH | 10.232 → 3.095 | 104.126 → 47.239 |
| LTC | 9.064 → 2.778 | 103.591 → 47.430 |
| DOGE | 2.677 → 0.641 | 13.554 → 1.456 |
| ETH | 7.380 → 2.596 | 106.288 → 59.596 |
| MATIC | 7.260 → 2.545 | 107.268 → 59.469 |
| ARB | 7.347 → 2.580 | 113.227 → 69.204 |
| BASE | 7.527 → 2.608 | 147.862 → 83.681 |
| OP | 7.425 → 2.684 | 129.004 → 71.980 |
| ARC | 7.975 → 2.733 | 124.449 → 65.949 |
| XRP | 9.780 → 3.065 | 103.742 → 47.854 |
| DOGE, cold | 10.072 → 7.076 | 60.405 → 47.984 |

Additional BTC workloads with native enabled measured 0.968 → 0.435 ms for 10 P2PKH, 7.670 → 2.869 ms for 100 P2WPKH, 9.880 → 4.855 ms for 100 P2TR, and 76.412 → 26.775 ms for 1,024 P2PKH addresses.

Build the addon and the crypto-wallet-core and bitcore-client TypeScript outputs to run `node native/bench-wallet-addresses.cjs --bench`. Run without `--bench` for parity checks, or set `BITCORE_ECDSA_BACKEND=js` with the fork selectors unset to exercise the JS-only path. The script accepts an optional absolute release `.node` path for the Bitcoin addon. Fork tests use their installed addons and selectors.

### Wallet scan, proposal signing and request authentication

* BWS recovery still probes the explorer sequentially and rewinds at the inactive gap. During a power scan it reuses each copayer’s parsed public branch key while reconstructing skipped BTC, BCH and LTC addresses. The address manager still supplies the paths and their order. On a 1,000-record BTC recovery with a stubbed explorer and storage, single-signature backfill and scanning fell from 87.45 to 55.59 ms and 2-of-3 P2WSH fell from 262.33 to 167.11 ms. Both comparisons use the same native backend. The parity corpus compares stored records, receive/change order, rewind indices, reprocessing flags, overrides and error propagation. [Recovery scan](../packages/bitcore-wallet-service/src/lib/server.ts) · [Benchmark](bench-bws-scan.cjs) · [Parity checks](test-bws-scan.cjs)
* [Wallet-client `Key.sign`](../packages/bitcore-wallet-client/src/lib/key.ts) deduplicates derivation by input path and shares the existing transaction sighash cache across multiple keys. The [branch-reuse benchmark](bench-wallet-signing.cjs) showed modest gains for distinct paths and no gain at 8 or 32 inputs sharing a key. Key derivation retains its per-path calls. For canonical BTC Taproot inputs, the native path matches each tweaked key to the spent output scripts and calls the existing signer and verifier for the matching inputs. Custom signing or randomness hooks and unsupported scripts use the per-key signer. [The wallet signature harness](test-wallet-signatures.cjs) verifies duplicates, ordering, script matching independently of path labels, external outputs, and fallback behavior.

The wallet signature harness with `--bench` compares the previous per-key signer and current implementation. These are medians of five alternating samples on Node 24.20.0 with the native addon.

| BTC proposal | Previous ms | Updated ms | Speedup |
| --- | ---: | ---: | ---: |
| 32 P2PKH inputs and keys | 6.54 | 5.06 | 1.29× |
| 100 P2PKH inputs and keys | 26.47 | 16.78 | 1.58× |
| 32 P2WPKH inputs and keys | 5.34 | 4.60 | 1.16× |
| 100 P2WPKH inputs and keys | 22.66 | 16.40 | 1.38× |
| 32 P2TR inputs and keys | 232.46 | 11.83 | 19.64× |
| 100 P2TR inputs and keys | 2,170.52 | 36.57 | 59.35× |

Repeating the same harness with the repository’s pinned Node 24.22.3 and all four native backends forced, 100-key P2PKH fell from 19.64 to 11.50 ms, P2WPKH from 17.11 to 12.24 ms, and P2TR from 1,008.94 to 18.59 ms (54.26×).

* [Node verification](../packages/bitcore-node/src/utils/auth.ts) and [BWS verification](../packages/bitcore-wallet-service/src/lib/common/utils.ts) already call compiled secp256k1 v4. The [offline auth harness](../packages/bitcore-client/benchmark/auth-crypto.mjs) measured valid native compact verification at 43.49 µs through v4 and 33.08 µs through the addon with an explicit low-S check. BWS DER import and verification measured 37.13 µs and 26.71 µs with the same comparison, with DER import still using v4. The valid-only measurements exclude routing and wallet/copayer lookup. The current adapters retain v4's low-S policy and malformed-input behavior. Bitcore Client already uses the Rust signer and `BulkClient.getStatusAll` signs once for the shared request key. BWS still authorizes each identity against its own copayer record.

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

The original paired benchmark on Linux x64 with Node 24.22.3 and a Core Ultra 9 275HX produced these median `processBlock` latencies with MongoDB mocked. It alternated seven rounds and reported milliseconds per block. The expanded fixtures reuse transactions from the repository's wire-format blocks with distinct lock times.

| Fixture | Transactions | Before ms | After ms | Speedup |
| --- | ---: | ---: | ---: | ---: |
| BTC block 357238 | 369 | 14.68 | 11.29 | 1.30× |
| BTC expanded | 2,001 | 69.19 | 55.17 | 1.25× |
| LTC witness | 1,201 | 60.73 | 43.98 | 1.38× |
| BCH CashTokens | 1,201 | 49.61 | 35.12 | 1.41× |
| DOGE expanded | 1,201 | 26.75 | 19.88 | 1.35× |
