# RPC and node chain cryptography

| Path | Local work and boundary |
| --- | --- |
| EVM and ERC20 signing and keystores | [EthRpc](../packages/crypto-rpc/lib/eth/EthRpc.js) imports private keys into the Web3 wallet. [Erc20Rpc](../packages/crypto-rpc/lib/erc20/Erc20Rpc.js) also encodes calldata locally. Both use the context-bound Web3 signer. The stubbed signer requested `eth_chainId` and `net_version` even with gas, price and nonce supplied. Web3 still prepares, signs and validates these transactions. The recoverable secp256k1 signing export has no hook in that call. The wrapper has no V3 keystore encrypt/decrypt entry point. Web3 exposes local scrypt or PBKDF2, AES-128-CTR and Keccak MAC through its accounts API. The Geth fixture keystore and `personal` account calls run on the daemon. |
| EVM raw decode | Ethers still parses and serializes the transaction and computes its ID. The local decoder uses optional Node-API recovery for canonical legacy, access-list and EIP-1559 signatures. The unsigned hash uses optional Keccak for preimages up to 4 KiB. Larger preimages use ethers Keccak. Unsupported signatures and types use ethers sender recovery. ERC20 and other EVM RPCs inherit the decoder. |
| XRP | [XrpRpc](../packages/crypto-rpc/lib/xrp/XrpRpc.js) derives the wallet locally, then calls `autofill`. The [wallet helper](../packages/crypto-rpc/lib/xrp/wallet.js) uses XRPL to decode the family seed and construct the wallet. The optional addon derives and self-tests secp256k1 and Ed25519 keypairs, with SDK fallback when native derivation is unavailable. The seed version selects the algorithm, and secp256k1 wallets use account index zero. Unsigned XRP payments can reuse native signing. XRPL still validates, encodes, and checks the resulting blob, and other payment shapes use `Wallet.sign`. After XRPL decodes a signed transaction, Node computes its SHA-512-half ID over the exact `54 58 4E 00` prefix and transaction bytes. |
| SOL and SPL | [SolRpc](../packages/crypto-rpc/lib/sol/SolRpc.js) passes supplied signers into Kit, including local WebCrypto Ed25519 `CryptoKey` signers. This API also accepts signer behavior provided by the caller. The seed-based native export takes a different key representation. No wallet encryption/decryption entry point was found in either RPC. `deriveAta` already calls the CWC token provider and inherits the optional local PDA implementation. SDK fallback uses SHA-256 and an Ed25519 point rejection check. Blockhash and nonce fetches, account lookups, and [ATA creation](../packages/crypto-rpc/lib/sol/SplRpc.js) still follow the existing RPC flow. |
| LND and UTXO RPCs | [LndRpc](../packages/crypto-rpc/lib/lnd/LndRpc.js) delegates wallet seed generation, initialization, unlock, and invoice signing to LND over gRPC, including with a loopback endpoint. The Lightning SDK locally parses the returned BOLT11 invoice and recovers its public key with tiny-secp256k1. That parser sits inside the SDK's RPC helper. [BtcRpc](../packages/crypto-rpc/lib/btc/BtcRpc.js) and its BCH/LTC/DOGE variants delegate wallet operations and raw decoding to their daemons. |
| Node EVM ingestion | The [transaction model](../packages/bitcore-node/src/providers/chain-state/evm/models/transaction.ts), query and stream transforms, and Alchemy/Moralis adapters normalize addresses locally. They share a bounded 4,096-entry checksum cache and use CWC's optional EIP-55 utility on misses, with Web3 fallback for older CWC installs. Instance-specific checksum functions still take precedence. Block hashes, roots and senders come from provider data. The verification peer checks stored chain and index consistency. |
| Node UTXO, XRP and Solana ingestion | BTC/BCH/LTC/DOGE P2P ingestion parses data through the coin packages and computes local header and transaction IDs and output addresses, including the P2PK HASH160 fallback in the [UTXO transaction model](../packages/bitcore-node/src/models/transaction.ts). The node's [UTXO verification peer](../packages/bitcore-node/src/modules/bitcoin/VerificationPeer.ts) checks stored chain and coin consistency. No node ingestion call to Merkle root validation, proof-of-work validation or script signature verification was found. Those operations remain coin-library APIs. XRP consumes ledger hashes and checks stored links. The [Solana provider](../packages/bitcore-node/src/providers/chain-state/svm/api/csp.ts) checks raw encoding/structure and derives ATAs for closed-account history. It uses provider signatures and status for indexed transactions. |

## Offline measurements

Linux x64, Core Ultra 9 275HX, Node 24.22.3, OpenSSL 3.5.9, using the installed release Node-API binary. Three alternating 220 ms samples per path after warmup. Rates are operations per second.

| Workload | SDK or uncached | Optimized |
| --- | ---: | ---: |
| EVM raw decode and sender recovery, mixed legacy and typed | 686 | 2,195 |
| EVM Web3 wallet signing with stubbed chain/network | 494 | |
| Web3 V3 keystore encrypt / decrypt, default scrypt | 67 / 65 | |
| XRP secp256k1 send, including seed derivation and signing (ABI 3) | 386 | 3,430 |
| XRP Ed25519 send, including seed derivation and signing (ABI 3) | 358 | 3,607 |
| XRP raw decode and signed transaction ID, XRPL vs. Node SHA-512-half | 9,597 | 18,478 |
| Solana complete SDK transfer signing | 6,356 | |
| Solana Ed25519 only, existing CryptoKey vs. native with seed | 28,070 | 46,421 |
| Solana RPC ATA derivation through CWC | 6,413 | 14,697 |
| EVM uncached address checksum, Web3 vs. CWC | 133,963 | 951,951 |
| EVM ingestion address normalization, 512 recurring addresses | 125,241 | 30,895,021 |
| EVM ingestion address normalization, 16,384 sequential addresses | 129,530 | 831,162 |
| LND SDK BOLT11 response parsing and recovery | 7,192 | |
| BTC fresh header parse/hash, transaction ID, P2PKH address | 375,055 / 351,266 / 149,266 | |

[bench-rpc.mjs](bench-rpc.mjs) uses synthetic in-memory keys and transactions, an in-process Web3 provider and an XRP autofill stub. It checks signed-byte and decoded-field parity, dispatch, and fallback behavior. Run it with Node 24 from the repo root. It accepts an optional absolute path to a release `.node` binary and otherwise uses the configured Bitcore backend. The checksum cache figure measures address lookups in isolation. The JS-only run measured about 4% cache overhead for single-use addresses. These measurements exclude network and storage, so they cover local throughput only.

### XRP family-seed derivation and full offline sends

Node 24.22.3 with the installed release ABI3 addon. Medians of three 400 ms samples after warmup, in operations per second. Wallet timings compare the SDK and the optional helper in the same process. Both `sendToAddress` runs use native transaction signing and stub `autofill` and `submit`. The baseline uses a release addon built from the checkout before adding native seed derivation.

| Workload | SDK derivation | Native derivation | Speedup |
| --- | ---: | ---: | ---: |
| secp256k1 wallet construction | 560 | 14,977 | 26.7× |
| Ed25519 wallet construction | 481 | 17,407 | 36.2× |
| secp256k1 `sendToAddress` | 443 | 3,407 | 7.7× |
| Ed25519 `sendToAddress` | 399 | 3,356 | 8.4× |

[test-xrp-keys.mjs](test-xrp-keys.mjs) checks 256 synthetic family seeds, 960 native keypairs against ripple-keypairs 1.3.1, 17 invalid seeds, and 64 byte-identical offline sends against xrpl 2.13.0. It covers conflicting algorithm options, numeric account-index wrapping, validator derivation, regular-wallet addresses, and the JavaScript fallback. The scalar retry and zero-sum cases, OS entropy failure, and cryptographic self-test failure were not forced.

From the repo root, run the installed-addon check and benchmark with `BITCORE_ECDSA_BACKEND=native node native/test-xrp-keys.mjs --bench` under Node 24. To reproduce the baseline, append `--no-derivation /path/to/baseline.node` using a release addon with the native signing exports and no `xrpDeriveKeypair` export.
