import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { performance } from 'node:perf_hooks';

const rootRequire = createRequire(import.meta.url);
const walletRequire = createRequire(rootRequire.resolve('@bitpay-labs/crypto-wallet-core'));
const loader = walletRequire.resolve('@bitpay-labs/bitcore-lib/lib/crypto/ecdsa-native');
walletRequire(loader);
const testOnly = process.argv[2] === '--test';
const addon = process.argv[2] && !testOnly ? rootRequire(resolve(process.argv[2])) : rootRequire.cache[loader].exports.native;
const selected = {};
// Exercise the real RPC methods with and without the new exports in one process.
// Override only the loader's exported object here, without replacing installed binaries.
rootRequire.cache[loader].exports = { native: selected };
const { BitcoreLib, ethers, SolKit, SolanaProgram, Utils, Web3, xrpl } = rootRequire('@bitpay-labs/crypto-wallet-core');

const { EthRpc } = await import('../packages/crypto-rpc/lib/eth/EthRpc.js');
const { XrpRpc } = await import('../packages/crypto-rpc/lib/xrp/XrpRpc.js');
const { SolRpc } = await import('../packages/crypto-rpc/lib/sol/SolRpc.js');
const { checksumAddress } = rootRequire('../packages/bitcore-node/src/providers/chain-state/evm/checksum-address.ts');

const rpcRequire = createRequire(new URL('../packages/crypto-rpc/lib/lnd/LndRpc.js', import.meta.url));
const lightningRequire = createRequire(rpcRequire.resolve('lightning'));
const { createSignedRequest, createUnsignedRequest, parsePaymentRequest } = lightningRequire('invoices');

const hash = value => createHash('sha256').update(String(value)).digest();
const privateKey = '0x' + hash('rpc benchmark').toString('hex');
const to = '0x' + hash('recipient').subarray(0, 20).toString('hex');
const evmSigner = new ethers.Wallet(privateKey);
const payment = { to, value: 42n, nonce: 0, chainId: 1n, gasLimit: 25000n };
const unsignedEvm = [
  { ...payment, type: 0, gasPrice: 10n },
  { ...payment, type: 1, gasPrice: 10n, accessList: [[to, ['0x' + '00'.repeat(32)]]] },
  { ...payment, type: 2, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n },
  { ...payment, type: 2, data: '0x' + 'aa'.repeat(4500), maxFeePerGas: 10n, maxPriorityFeePerGas: 1n },
];
const rawEvm = await Promise.all(unsignedEvm.map(tx => evmSigner.signTransaction(tx)));
const evmRpc = Object.create(EthRpc.prototype);
const decodeEvm = index => evmRpc.decodeRawTransaction({ rawTx: rawEvm[index % rawEvm.length] });
const calls = {};

function setNative(enabled) {
  for (const name of [
    'cwcEvmRecoverAddress', 'cwcKeccak256', 'cwcKeccak256Large', 'cwcChecksumAddress', 'cwcXrpSign',
    'cwcXrpSignLarge', 'ed25519Sign', 'ed25519SignLarge', 'solAssociatedTokenAddress', 'xrpDeriveKeypair'
  ]) {
    delete selected[name];
    if (enabled && typeof addon?.[name] === 'function') {
      selected[name] = (...args) => {
        calls[name] = (calls[name] || 0) + 1;
        return addon[name](...args);
      };
    }
  }
}

const fallbackEvm = rawEvm.map((_, index) => decodeEvm(index));
const unsigned = ethers.Transaction.from(unsignedEvm[0]).unsignedSerialized;
assert.equal(evmRpc.decodeRawTransaction({ rawTx: unsigned }).from, undefined);
const classical = ethers.Transaction.from(rawEvm[0]);
const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const legacy = ethers.decodeRlp(rawEvm[0]);
legacy[6] = classical.signature.yParity ? '0x25' : '0x26';
legacy[8] = ethers.toBeHex(order - BigInt(legacy[8]), 32);
const highS = ethers.encodeRlp(legacy);
const decodeOutcome = rawTx => {
  try {
    return evmRpc.decodeRawTransaction({ rawTx });
  } catch (err) {
    return [err.name, err.code, err.message];
  }
};
const fallbackHighS = decodeOutcome(highS);
const fallbackBadEvm = decodeOutcome('0x1234');
const blobTransaction = await evmSigner.signTransaction({
  ...payment, type: 3, maxPriorityFeePerGas: 1n, maxFeePerGas: 10n, maxFeePerBlobGas: 100n,
  blobVersionedHashes: ['0x01' + '00'.repeat(31)]
});
const fallbackBlob = decodeOutcome(blobTransaction);
setNative(true);
assert.deepEqual(rawEvm.map((_, index) => decodeEvm(index)), fallbackEvm);
if (addon?.cwcKeccak256 && addon?.cwcEvmRecoverAddress) {
  const hashesPerShortTx = addon.cwcKeccak256Large ? 2 : 1;
  assert.equal(calls.cwcKeccak256, (rawEvm.length - 1) * hashesPerShortTx);
}
if (addon?.cwcKeccak256Large && addon?.cwcEvmRecoverAddress) assert.equal(calls.cwcKeccak256Large, 2);
assert.deepEqual(decodeOutcome(highS), fallbackHighS);
assert.equal(evmRpc.decodeRawTransaction({ rawTx: unsigned }).from, undefined);
assert.deepEqual(decodeOutcome('0x1234'), fallbackBadEvm);
assert.deepEqual(decodeOutcome(blobTransaction), fallbackBlob);
if (addon?.cwcEvmRecoverAddress) assert.equal(calls.cwcEvmRecoverAddress, rawEvm.length);

const rpcMethods = new Set();
const web3 = new Web3({
  request: async ({ method, id, jsonrpc }) => {
    rpcMethods.add(method);
    assert.ok(method === 'eth_chainId' || method === 'net_version', method);
    return { id, jsonrpc, result: method === 'eth_chainId' ? '0x1' : '1' };
  }
});
const evmAccount = web3.eth.accounts.privateKeyToAccount(privateKey);
const signWeb3 = () => evmAccount.signTransaction({
  from: evmAccount.address, to, value: 42n, nonce: 0, gas: 25000n, gasPrice: 10n
});
assert.equal((await signWeb3()).rawTransaction, rawEvm[0]);
assert.deepEqual([...rpcMethods], ['eth_chainId', 'net_version']);
const encryptKeystore = () => evmAccount.encrypt('offline benchmark');
const keystore = await encryptKeystore();
const decryptKeystore = () => web3.eth.accounts.decrypt(keystore, 'offline benchmark');
assert.equal((await decryptKeystore()).address, evmAccount.address);
const invoiceId = hash('bolt-11 invoice').toString('hex');
const invoice = createUnsignedRequest({
  created_at: '2020-01-01T00:00:00.000Z', description: 'benchmark',
  id: invoiceId, mtokens: '1000', network: 'bitcoin'
});
const invoiceKey = new ethers.SigningKey(privateKey);
const invoiceSignature = invoiceKey.sign('0x' + invoice.hash);
const signedInvoice = createSignedRequest({
  destination: invoiceKey.compressedPublicKey.slice(2),
  hrp: invoice.hrp, tags: invoice.tags,
  signature: invoiceSignature.r.slice(2) + invoiceSignature.s.slice(2)
});
const parseInvoice = () => parsePaymentRequest(signedInvoice);
assert.equal(parseInvoice().id, invoiceId);

const xrpWallets = ['secp256k1', 'ed25519'].map((algorithm, index) =>
  xrpl.Wallet.fromEntropy(hash(index).subarray(0, 16), { algorithm })
);
const xrpRpc = Object.create(XrpRpc.prototype);
const xrpPay = xrpWallets.map((wallet, index) => ({
  address: xrpWallets[1 - index].address,
  amount: '0.000042', secret: wallet.seed, tag: 23, invoiceID: hash('invoice').toString('hex').toUpperCase()
}));
const prepare = tx => ({ ...tx, Fee: '12', Sequence: 7, LastLedgerSequence: 500, SourceTag: null });
xrpRpc.asyncCall = async (method, tx) => {
  assert.equal(method, 'autofill');
  return prepare(tx);
};
const payXrp = index => xrpRpc.signTransaction(xrpPay[index]);
const prepared = xrpWallets.map((wallet, index) => prepare({
  TransactionType: 'Payment', Account: wallet.address,
  Amount: '42', Destination: xrpPay[index].address, DestinationTag: 23, InvoiceID: xrpPay[index].invoiceID
}));
setNative(false);
const fallbackXrp = await Promise.all(xrpWallets.map((_, index) => payXrp(index)));
setNative(true);
assert.deepEqual(await Promise.all(xrpWallets.map((_, index) => payXrp(index))), fallbackXrp);
if (addon?.cwcXrpSign) assert.equal(calls.cwcXrpSign, 1);
if (addon?.ed25519Sign) assert.equal(calls.ed25519Sign, 1);
if (addon?.xrpDeriveKeypair) assert.equal(calls.xrpDeriveKeypair, xrpWallets.length);
for (const [index, blob] of fallbackXrp.entries()) {
  assert.equal(blob, xrpWallets[index].sign(prepared[index]).tx_blob);
  assert.ok(xrpWallets[index].verifyTransaction(blob));
}
const decodeXrp = i => xrpRpc.decodeRawTransaction({ rawTx: fallbackXrp[i % fallbackXrp.length] });
const sdkDecodeXrp = async i => {
  const rawTx = fallbackXrp[i % fallbackXrp.length];
  const tx = xrpl.decode(rawTx);
  if (tx.TxnSignature) tx.hash = xrpl.hashes.hashSignedTx(rawTx);
  return tx;
};
const lowerCaseXrp = { rawTx: fallbackXrp[0].toLowerCase() };
const fallbackDecodedXrp = await sdkDecodeXrp(0);
assert.deepEqual(await decodeXrp(0), fallbackDecodedXrp);
assert.deepEqual(await xrpRpc.decodeRawTransaction(lowerCaseXrp), fallbackDecodedXrp);
const unsignedXrp = xrpl.encode({ ...prepared[0], SourceTag: 0 });
assert.deepEqual(await xrpRpc.decodeRawTransaction({ rawTx: unsignedXrp }), xrpl.decode(unsignedXrp));
const expectedXrpHash = createHash('sha512').update(Buffer.from('54584e00' + fallbackXrp[0], 'hex')).digest('hex');
assert.equal(fallbackDecodedXrp.hash, expectedXrpHash.slice(0, 64).toUpperCase());
for (const [name, index, invalid, message] of [
  ['ed25519Sign', 1, new Uint8Array(96), 'Invalid native XRP Ed25519 result'],
  ['ed25519Sign', 1, Buffer.alloc(95), 'Invalid native XRP Ed25519 result'],
  ['cwcXrpSign', 0, new Uint8Array(70), 'Invalid native XRP DER signature'],
  ['cwcXrpSign', 0, Buffer.alloc(7), 'Invalid native XRP DER signature'],
  ['cwcXrpSign', 0, Buffer.alloc(70), 'Invalid native XRP DER signature']
]) {
  if (!addon?.[name]) continue;
  selected[name] = () => invalid;
  await assert.rejects(payXrp(index), { message });
  setNative(true);
}
for (const override of [
  { Fee: {} },
  { TxnSignature: 'FF' },
  { Amount: { currency: 'USD', issuer: xrpWallets[0].address, value: '1.00' } }
]) {
  const originalAutofill = xrpRpc.asyncCall;
  xrpRpc.asyncCall = async (...args) => ({ ...await originalAutofill(...args), ...override });
  const outcome = async () => payXrp(1).catch(err => [err.name, err.message]);
  setNative(false);
  const fallback = await outcome();
  setNative(true);
  assert.deepEqual(await outcome(), fallback);
  xrpRpc.asyncCall = originalAutofill;
}
for (const [index, method, memoLength] of [[0, 'cwcXrpSignLarge', 4200], [1, 'ed25519SignLarge', 1500]]) {
  const originalAutofill = xrpRpc.asyncCall;
  xrpRpc.asyncCall = async (...args) => ({
    ...await originalAutofill(...args), Memos: [{ Memo: { MemoData: 'AB'.repeat(memoLength) } }]
  });
  setNative(false);
  const expected = await payXrp(index);
  setNative(true);
  const before = calls[method] || 0;
  assert.equal(await payXrp(index), expected);
  if (addon?.[method]) assert.equal(calls[method], before + 1);
  delete selected[method];
  assert.equal(await payXrp(index), expected);
  xrpRpc.asyncCall = originalAutofill;
}
setNative(true);

const seed = hash('sol signer');
const solSigner = await SolKit.createKeyPairSignerFromPrivateKeyBytes(seed);
const solDestination = (await SolKit.createKeyPairSignerFromPrivateKeyBytes(hash('sol destination'))).address;
const solTransfer = SolanaProgram.System.getTransferSolInstruction({
  source: solSigner, destination: solDestination, amount: 1n
});
const solMessage = SolKit.appendTransactionMessageInstructions([solTransfer],
  SolKit.setTransactionMessageLifetimeUsingBlockhash({ blockhash: solDestination, lastValidBlockHeight: 10n },
    SolKit.setTransactionMessageFeePayerSigner(solSigner, SolKit.createTransactionMessage({ version: 0 }))));
const signedSol = await SolKit.signTransactionMessageWithSigners(solMessage);
const signSolBytes = () => SolKit.signBytes(solSigner.keyPair.privateKey, signedSol.messageBytes);
const mintAddress = SolKit.address('So11111111111111111111111111111111111111112');
const deriveAta = () => SolRpc.prototype.deriveAta({ solAddress: solDestination, mintAddress });
setNative(false);
const sdkAta = await deriveAta();
setNative(true);
assert.equal(await deriveAta(), sdkAta);
assert.equal(await deriveAta(), (await SolanaProgram.Token.findAssociatedTokenPda({
  owner: solDestination, mint: mintAddress, tokenProgram: SolanaProgram.Token.TOKEN_PROGRAM_ADDRESS
}))[0]);
if (addon?.ed25519Sign) {
  assert.deepEqual(addon.ed25519Sign(seed, signedSol.messageBytes).subarray(32), Buffer.from(await signSolBytes()));
}

const addresses = Array.from({ length: 16384 }, (_, index) => '0x' + hash(index).subarray(0, 20).toString('hex'));
for (const address of [addresses[0], addresses[1].slice(2), addresses[2].toUpperCase(), Web3.utils.toChecksumAddress(to)]) {
  assert.equal(checksumAddress(address), Web3.utils.toChecksumAddress(address));
}
assert.throws(() => checksumAddress('0x01'), { name: 'InvalidAddressError' });
assert.equal(checksumAddress('mock', { toChecksumAddress: address => address }), 'mock');
if (Utils.toChecksumAddress && addon?.cwcChecksumAddress) assert.ok(calls.cwcChecksumAddress > 0);
const output = BitcoreLib.Script.buildPublicKeyHashOut(BitcoreLib.Address.fromPublicKeyHash(hash('btc').subarray(0, 20)));
const tx = new BitcoreLib.Transaction().addOutput(new BitcoreLib.Transaction.Output({ script: output, satoshis: 1000 }));
const headerBytes = Buffer.alloc(80);

if (testOnly) {
  assert.equal(typeof addon?.cwcKeccak256Large, 'function');
  console.log('Offline RPC compatibility and native dispatch checks passed.');
  process.exit(0);
}

async function sample(run, before) {
  before?.();
  const first = run(0);
  const isAsync = first instanceof Promise;
  if (isAsync) await first;
  const warmup = performance.now() + 120;
  for (let i = 0; performance.now() < warmup; i++) {
    if (isAsync) await run(i);
    else run(i);
  }
  const start = performance.now();
  let count = 0;
  while (performance.now() - start < 220) {
    if (isAsync) await run(count);
    else run(count);
    count++;
  }
  return count * 1000 / (performance.now() - start);
}

async function bench(label, baseline, candidate, toggle = false) {
  const jobs = [
    { run: baseline, before: toggle ? () => setNative(false) : undefined, rates: [] },
    ...(candidate ? [{ run: candidate, before: toggle ? () => setNative(true) : undefined, rates: [] }] : [])
  ];
  for (let round = 0; round < 3; round++) {
    for (const { run, before, rates } of round % 2 ? [...jobs].reverse() : jobs) rates.push(await sample(run, before));
  }
  console.log(label, jobs.map(({ rates }) => Math.round(rates.sort((a, b) => a - b)[1])).join(' → '));
}

console.log('Node', process.version, 'OpenSSL', process.versions.openssl, '(median ops/s)');
await bench('EVM Web3 wallet.signTransaction (stub chain/network)', signWeb3);
await bench('EVM Web3 V3 keystore encrypt', encryptKeystore);
await bench('EVM Web3 V3 keystore decrypt', decryptKeystore);
await bench('EVM RPC raw decode and sender recovery', decodeEvm, addon?.cwcEvmRecoverAddress && decodeEvm, true);
await bench('XRP secp256k1 RPC autofill stub and signing', () => payXrp(0), addon?.cwcXrpSign && (() => payXrp(0)), true);
await bench('XRP Ed25519 RPC autofill stub and signing', () => payXrp(1), addon?.ed25519Sign && (() => payXrp(1)), true);
await bench('XRP RPC raw decode and transaction ID', sdkDecodeXrp, decodeXrp);
await bench('XRP secp256k1 Wallet.fromSeed', () => xrpl.Wallet.fromSeed(xrpWallets[0].seed));
await bench('Solana SDK sign complete transfer', () => SolKit.signTransactionMessageWithSigners(solMessage));
await bench('Solana Ed25519 primitive (CryptoKey → seed-based native)', signSolBytes,
  addon?.ed25519Sign && (() => addon.ed25519Sign(seed, signedSol.messageBytes)));
await bench('Solana RPC ATA derivation', deriveAta, addon?.solAssociatedTokenAddress && calls.solAssociatedTokenAddress && deriveAta, true);
await bench('LND SDK parse BOLT11 response and recover node key', parseInvoice);
await bench('EVM CWC checksum on uncached addresses',
  i => Web3.utils.toChecksumAddress(addresses[i % addresses.length]),
  Utils.toChecksumAddress && addon?.cwcChecksumAddress && (i => Utils.toChecksumAddress(addresses[i % addresses.length])), true);
setNative(true);
await bench('EVM ingestion checksum, 512 recurring addresses',
  i => Web3.utils.toChecksumAddress(addresses[i % 512]), i => checksumAddress(addresses[i % 512]));
await bench('EVM ingestion checksum, 16384 sequential addresses',
  i => Web3.utils.toChecksumAddress(addresses[i % addresses.length]), i => checksumAddress(addresses[i % addresses.length]));
await bench('Bitcoin initial header hash including parse', () => new BitcoreLib.BlockHeader(headerBytes).hash);
await bench('Bitcoin transaction hash', () => tx.hash);
await bench('Bitcoin P2PKH script address', () => output.toAddress().toString());
