/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS benchmark. */
'use strict';

const assert = require('node:assert/strict');
const { performance } = require('node:perf_hooks');
const { Web3 } = require('web3');
const { ERC20TxProvider } = require('../ts_build/src/transactions/erc20');
const { ERC20Abi, MULTISENDAbi } = require('../ts_build/src/transactions/erc20/abi');
const { ETHTxProvider } = require('../ts_build/src/transactions/eth');
const { ETHMULTISIGTxProvider } = require('../ts_build/src/transactions/eth-multisig');
const { MultisigAbi } = require('../ts_build/src/transactions/eth-multisig/abi');

const iterations = Number(process.argv[2] ?? 10000);
const mode = process.argv[3];
assert(Number.isSafeInteger(iterations) && iterations > 0);
assert(!mode || mode === 'fresh' || mode === 'default');

const address = value => '0x' + value.toString(16).padStart(40, '0');
const tokenAddress = address(123);
const recipients = [
  { address: address(456), amount: '1000000000000000000' },
  { address: address(789), amount: '25' }
];
const params = { recipients, tokenAddress, nonce: 1, gasPrice: 10, gasLimit: 120000, network: 'mainnet' };

const eth = new ETHTxProvider();
const erc20 = new ERC20TxProvider();
const multisig = new ETHMULTISIGTxProvider();
const freshEth = new ETHTxProvider();
const freshErc20 = new ERC20TxProvider();
const freshMultisig = new ETHMULTISIGTxProvider();
function freshContract(abi, to) {
  const web3 = new Web3();
  return new web3.eth.Contract(abi, to);
}
freshEth.getMultiSendContract = freshErc20.getMultiSendContract = to => freshContract(MULTISENDAbi, to);
freshErc20.getERC20Contract = to => freshContract(ERC20Abi, to);
freshMultisig.getMultisigContract = to => freshContract(MultisigAbi, to);

const cases = [
  ['ETH multisend create', eth, freshEth, (provider, to) => provider.create({ ...params, contractAddress: to })],
  ['ERC20 transfer create', erc20, freshErc20, (provider, to) => provider.create({ ...params, recipients: [recipients[0]], tokenAddress: to })],
  ['ERC20 multisend create', erc20, freshErc20, (provider, to) => provider.create({ ...params, contractAddress: to })],
  ['Multisig add owner calldata', multisig, freshMultisig, (provider, to) => provider.addOwnerEncodeData({ multisigContractAddress: to, newOwnerAddress: recipients[0].address })]
];
const targets = Array.from({ length: 256 }, (_, i) => address(1000 + i));

function run(operation, provider, count) {
  const start = performance.now();
  for (let i = 0; i < count; i++) operation(provider, targets[i % targets.length]);
  return (performance.now() - start) * 1000 / count;
}

console.log(`Node ${process.version}, median μs/op over 5 rounds of ${iterations} calls per case`);
for (const [name, provider, freshProvider, operation] of cases) {
  const variants = [['fresh', freshProvider], ['default', provider]].filter(([label]) => !mode || mode === label);
  if (!mode) {
    for (const to of targets) assert.equal(operation(provider, to), operation(freshProvider, to));
  }
  const samples = variants.map(() => []);
  for (const [, implementation] of variants) run(operation, implementation, 1000);
  for (let round = 0; round < 5; round++) {
    for (let offset = 0; offset < variants.length; offset++) {
      const index = (round + offset) % variants.length;
      samples[index].push(run(operation, variants[index][1], iterations));
    }
  }
  const medians = samples.map(times => times.sort((a, b) => a - b)[2]);
  const columns = variants.map(([label], i) => `${label} ${medians[i].toFixed(1)}`);
  if (!mode) columns.push(`${(medians[0] / medians[1]).toFixed(2)}x`);
  console.log(`${name.padEnd(30)} ${columns.join(' | ')}`);
}
