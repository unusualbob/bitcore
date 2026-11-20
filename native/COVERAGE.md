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

On Linux x64 with Node 24.22.3, the committed baseline passed 19,119 tests across 18 offline suites, with 16 pending. Forcing JavaScript and then ABI 3 produced the same 19,136 passing and 16 pending test identities in each run. These runs covered the four coin libraries, three P2P packages, mnemonic, CWC, TSS, wallet packages, and offline node, RPC and CLI tests. The comparison excludes live chain daemons, MongoDB integration suites and the client wallet test requiring the missing bcrypt binding. Browserify produced bundles for all four coin libraries. The [RPC coverage report](RPC-COVERAGE.md) identifies operations measured with provider calls stubbed.

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
| Sign XRP payment with secp256k1 | 979 | 2,873 | 2.93× |
| Sign XRP payment with Ed25519 | 925 | 3,192 | 3.45× |
| Derive an XRP address from a public key | 128,981 | 208,582 | 1.62× |

An isolated Rust SHA-512-half binding achieved 796,527 XRP hashes per second versus 923,089 with Node crypto, about 0.86×. The public transaction-hash method retains Node's SHA-512 implementation. Native secp256k1 transaction signing computes SHA-512-half inside the signing call.

The corpus covers all six EVM chains, their token routes, and both multisig providers. It compares transaction types 0, 1, and 2, malformed signature scalars and legacy V encodings, ECDSA nonce inputs at and above the curve order, and Unicode and long messages. The XRP corpus covers secp256k1 and Ed25519 keys, ticket transactions, issued amounts, multisign hashes, special key and preimage formats, and vendor signature verification. XRPL remains responsible for validation, codecs, and SDK verification.

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

The transaction and block parsers continue to construct the existing JavaScript objects and handle witness, CashTokens and AuxPoW wire formats. Partial Merkle proofs retain their flag traversal and malformed-proof handling. Script interpreters retain opcode, stack and error semantics and call the optimized signature APIs.

## Wallet imports, authentication and shared arithmetic

The rows below compare each public operation with its previous implementation on Node 24.22.3. The Bitcoin-family message rows enable the previous native recovery path in both measurements, isolating the gain from moving randomized signing into libsecp256k1. JavaScript still draws the nonce.

| Workload | Measured improvement | Implementation |
| --- | ---: | --- |
| Bitcore Client request signing | 21.3× | Rust addon replaces the installed elliptic fallback. Node and BWS authentication already load compiled secp256k1. |
| BTC/BCH/LTC/DOGE wallet message signing | 4.8–4.9× | One candidate nonce per native signing call, including retries |
| Canonical public point validation | 39–52× | Curve equation using secp256k1's cofactor of one |
| Construct a point from its x coordinate | 21–26× | Existing Rust SEC parser |
| BCH square test on a point | 22–23× | Jacobi symbol using V8 BigInt |
| Base58 decode, 25 bytes | 3.02× | Batched radix conversion in JavaScript |
| Extended-key Base58Check encode / decode | 1.61× / 2.25× | Batched radix conversion and Node hashing |
| HMAC-SHA256 / HMAC-SHA512 | 1.42× / 1.94× | Node crypto |
| Bitcoin Core wallet import KDF, 200,000 rounds | 5.3–5.7× | Repeated SHA-512 in Rust |
| BIP38 scrypt | 1,133 ms → 170 ms | Node/OpenSSL. Progress callbacks use the original implementation. |

Wallet password PBKDF2 at 600,000 iterations measured 52.13 ms in OpenSSL and 45.47 ms in a standalone Rust release on one core, and 49.12 versus 47.87 ms on another. The wallet keeps OpenSSL and reuses decrypted data within a single operation. Creating Bitcoin credentials now takes two password derivations, down from four. Solana credentials take three, down from six. BIP37 Bloom hashing measured about three million inserts or hits per second with the existing JavaScript implementation. Public BN and elliptic methods preserve their object and prototype contracts.

The [wallet KDF](bench-wallet-kdfs.cjs), [client authentication](../packages/bitcore-client/benchmark/auth-crypto.mjs), [message signing](bench-random-nonce.cjs), [encoding](bench-encoding.cjs) and [public point](../packages/bitcore-lib/benchmark/point.js) benchmarks record their respective fixtures and comparison modes.

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
