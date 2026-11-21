import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { Erc20Rpc } from '../packages/crypto-rpc/lib/erc20/Erc20Rpc.js';
import { EthRpc } from '../packages/crypto-rpc/lib/eth/EthRpc.js';

const require = createRequire(import.meta.url);
const walletRequire = createRequire(require.resolve('@bitpay-labs/crypto-wallet-core'));
const { Web3, eth, types, utils } = walletRequire('web3');
const { cwcSignRecoverable } = require(process.argv[2]
  ? resolve(process.argv[2])
  : '../packages/bitcore-lib/lib/native/bitcore_ecdsa.node');
assert.equal(typeof cwcSignRecoverable, 'function');

const fixture = value => createHash('sha256').update(value).digest('hex');
const privateKey = '0x' + fixture('offline Web3 signing benchmark');
const to = '0x' + fixture('fixture recipient').slice(0, 40);
const token = '0x' + fixture('fixture token').slice(0, 40);
const rpcResults = {
  eth_chainId: '0x539',
  net_version: '1338',
  eth_estimateGas: '0xea60',
  eth_getTransactionCount: '0x0'
};

function stubWeb3(calls) {
  return new Web3({
    async request({ method, params, id, jsonrpc }) {
      assert.ok(Object.hasOwn(rpcResults, method), method);
      calls.push([method, params]);
      return { id, jsonrpc, result: rpcResults[method] };
    }
  });
}

// Diagnostic only. Calling prepare+sign separately bypasses the account's signer.
// Web3 freezes the transaction, so this replacement borrows an undocumented
// protected method on a disposable object. No SDK object or prototype is modified.
async function probe(web3, tx, key) {
  const prepared = await eth.prepareTransactionForSigning(tx, web3);
  assert.ok(Object.isFrozen(prepared));
  const instrumented = Object.create(prepared, {
    _ecsign: {
      value(digest, secret, chainId) {
        const keyBuffer = Buffer.from(secret);
        try {
          const sig = cwcSignRecoverable(Buffer.from(digest), keyBuffer);
          assert.ok(Buffer.isBuffer(sig) && sig.length === 65);
          const recovery = BigInt(sig[64]);
          const v = chainId === undefined ? recovery + 27n : recovery + 35n + 2n * chainId;
          return { v, r: sig.subarray(0, 32), s: sig.subarray(32, 64) };
        } finally {
          keyBuffer.fill(0);
        }
      }
    }
  });
  return eth.accounts.signTransaction(instrumented, utils.format({ format: 'bytes' }, key, types.ETH_DATA_FORMAT));
}

const calls = [];
const web3 = stubWeb3(calls);
const account = web3.eth.accounts.privateKeyToAccount(privateKey);
const payment = { from: account.address, to, value: '42', nonce: 0, gas: 60_000n };
const inputs = [
  { ...payment, gasPrice: 10n },
  { ...payment, type: 1, gasPrice: 10n, accessList: [{ address: to, storageKeys: ['0x' + '00'.repeat(32)] }] },
  { ...payment, type: 2, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n },
  { ...payment, type: 0, gasPrice: 10n, hardfork: 'homestead' }
];

async function capture(run) {
  calls.length = 0;
  try {
    return { result: await run(), calls: calls.slice() };
  } catch (error) {
    return { error: [error.name, error.code, error.message], calls: calls.slice() };
  }
}

for (const [i, tx] of inputs.entries()) {
  const expected = await capture(() => account.signTransaction(tx));
  assert.ok(expected.result, `Fixture ${i}: ${JSON.stringify(expected.error)}`);
  assert.deepEqual(expected.calls, [['eth_chainId', []], ['net_version', []]]);
  assert.deepEqual(await capture(() => probe(web3, tx, privateKey)), expected);
}
for (const tx of [{ ...inputs[0], gas: 1n }, { ...inputs[0], to: '0x01' }]) {
  const expected = await capture(() => account.signTransaction(tx));
  assert.ok(expected.error);
  assert.deepEqual(await capture(() => probe(web3, tx, privateKey)), expected);
}

async function checkWrapper(Rpc) {
  const requests = [];
  const signerContext = stubWeb3(requests);
  const broadcasts = [];
  const rpc = new class extends Rpc {
    getWeb3() {
      return signerContext;
    }
    sendRawTransaction({ rawTx }) {
      broadcasts.push(rawTx);
      return rawTx;
    }
  }({ tokenContractAddress: token });
  const address = rpc.addAccount(privateKey);
  const args = { address: to, amount: 42, gasPrice: 10n, nonce: 0, gas: 60_000n };
  const wallet = signerContext.eth.accounts.wallet.get(address);
  const stockSign = wallet.signTransaction.bind(wallet);
  const stockRaw = await rpc.sendToAddress(args);
  const expectedCalls = requests.splice(0);
  const nativeSign = tx => probe(signerContext, tx, privateKey);
  wallet.signTransaction = nativeSign;
  assert.equal(await rpc.sendToAddress(args), stockRaw);
  assert.deepEqual(requests.splice(0), expectedCalls);
  assert.deepEqual(broadcasts.splice(0), [stockRaw, stockRaw]);

  wallet.signTransaction = stockSign;
  const autofillArgs = { ...args, gas: undefined, nonce: undefined };
  assert.equal(await rpc.sendToAddress(autofillArgs), stockRaw);
  const autofillCalls = requests.splice(0);
  assert.deepEqual(autofillCalls.map(([method]) => method), ['eth_estimateGas', 'eth_getTransactionCount',
    'eth_chainId', 'net_version']);
  wallet.signTransaction = nativeSign;
  assert.equal(await rpc.sendToAddress(autofillArgs), stockRaw);
  assert.deepEqual(requests.splice(0), autofillCalls);
  assert.deepEqual(broadcasts.splice(0), [stockRaw, stockRaw]);

  // Web3's signer closes over a different account object than the wallet entry.
  // A replacement using the entry's exposed privateKey can choose another key.
  wallet.signTransaction = stockSign;
  const originalKey = wallet.privateKey;
  const replacementKey = '0x' + fixture('different fixture key');
  wallet.privateKey = replacementKey;
  assert.equal(await rpc.sendToAddress(args), stockRaw);
  wallet.signTransaction = tx => probe(signerContext, tx, wallet.privateKey);
  assert.notEqual(await rpc.sendToAddress(args), stockRaw);
  wallet.privateKey = originalKey;
  requests.length = broadcasts.length = 0;

  const signerError = new Error('custom signer rejected the request');
  const customAddress = '0x' + fixture('custom account').slice(0, 40);
  const supplied = [];
  signerContext.eth.accounts.wallet.add({
    address: customAddress,
    get privateKey() { throw new Error('Unexpected access to the custom signer key'); },
    async signTransaction(tx) {
      supplied.push(tx);
      if (supplied.length > 1) throw signerError;
      return { rawTransaction: stockRaw };
    }
  });
  const customArgs = { ...args, fromAccount: customAddress };
  assert.equal(await rpc.sendToAddress(customArgs), stockRaw);
  await assert.rejects(rpc.sendToAddress(customArgs), error => error === signerError);
  assert.equal(supplied.length, 2);
  assert.equal(supplied[0].from, customAddress);
  assert.equal(supplied[0].to, Rpc === Erc20Rpc ? token : to);
  if (Rpc === Erc20Rpc) assert.match(supplied[0].data, /^0xa9059cbb/);
  assert.deepEqual(requests, []);
  assert.deepEqual(broadcasts, [stockRaw]);
  return {
    select: sign => { wallet.signTransaction = sign; },
    signers: [stockSign, nativeSign],
    run: () => rpc.sendToAddress(args),
    reset: () => { requests.length = broadcasts.length = 0; }
  };
}

async function sample(run, reset) {
  const warmup = performance.now() + 150;
  while (performance.now() < warmup) {
    await run();
    reset();
  }
  const start = performance.now();
  let count = 0;
  do {
    await run();
    reset();
    count++;
  } while (performance.now() - start < 450);
  return count * 1000 / (performance.now() - start);
}

console.log('Node', process.version, '(median ops/s, mock provider and broadcast)');
for (const Rpc of [EthRpc, Erc20Rpc]) {
  const { select, signers, run, reset } = await checkWrapper(Rpc);
  const jobs = signers.map(sign => ({ sign, rates: [] }));
  for (let round = 0; round < 5; round++) {
    for (const { sign, rates } of round % 2 ? [...jobs].reverse() : jobs) {
      select(sign);
      rates.push(await sample(run, reset));
    }
  }
  const medians = jobs.map(({ rates }) => Math.round(rates.sort((a, b) => a - b)[2]));
  console.log(Rpc.name, medians.join(' → '));
}
