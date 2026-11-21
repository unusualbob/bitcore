# Crypto Wallet Core

**A coin-agnostic wallet library for creating transactions, signing, and address derivation.**

## Transaction encoding and derivation benchmarks

ETH multisend, ERC20, and ETH and Polygon multisig builders reuse function selectors for the bundled ABIs. They use Web3 for argument validation and parameter encoding. Contract getters still return fresh, mutable Web3 contracts. Getter overrides, edits to the exported ABIs (including shared nested data exposed by a returned contract), and unusual contract addresses take the original Web3 construction path.

Run from the repository root with dependencies already installed.

```sh
npm run build --workspace @bitpay-labs/crypto-wallet-core
node packages/crypto-wallet-core/benchmark/evm-contract-encoding.js 2000
node packages/crypto-wallet-core/benchmark/xrp-key-derivation.js
```

The EVM benchmark checks byte-for-byte equality against builders using fresh Web3 contracts over 256 contract addresses. To profile the fresh-contract baseline, use Node's CPU profiler and select the `fresh` variant.

```sh
node --cpu-prof --cpu-prof-dir=/tmp packages/crypto-wallet-core/benchmark/evm-contract-encoding.js 2000 fresh
```

On Node 20.20.2, Web3's ABI signature encoders appeared in 63% of sampled JavaScript stacks in the `fresh` profile and 0.2% in the `default` profile, which includes selector initialization. The `default` profile had zero samples in Web3's contract ABI parser. A local benchmark run produced these median times.

| Operation | Baseline (μs/op) | Optimized (μs/op) | Speedup |
| --- | ---: | ---: | ---: |
| ETH multisend transaction | 853.4 | 127.5 | 6.69× |
| ERC20 transfer transaction | 741.8 | 80.2 | 9.25× |
| ERC20 multisend transaction | 752.6 | 115.6 | 6.51× |
| Multisig add-owner calldata | 2413.1 | 239.0 | 10.10× |
| XRP private derivation (`BITCORE_ECDSA_BACKEND=auto`) | 156.1 | 112.9 | 1.38× |

The XRP benchmark measures full private derivation on new paths, including address derivation. Reading the derived keys directly avoids materializing an extended public key and serializing both extended keys. The public-only derivation showed a difference below 1% and still uses its existing path.

## Contributing

See [CONTRIBUTING.md](https://github.com/bitpay/bitcore/blob/master/CONTRIBUTING.md) on the main bitcore repo for information about how to contribute.

## License

Code released under [the MIT license](https://github.com/bitpay/bitcore/blob/master/LICENSE).

Copyright 2013-2025 BitPay, Inc. Bitcore is a trademark maintained by BitPay, Inc.
