/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS test. */
'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');

function runCorpus() {
  const counts = new Map();
  let addon;
  if (process.env.BITCORE_ECDSA_BACKEND === 'native') {
    addon = require('../packages/bitcore-lib/lib/native/bitcore_ecdsa.node');
    for (const name of ['cwcKeccak256', 'cwcEvmAddress', 'cwcEvmRecoverAddress', 'cwcSignRecoverable',
      'cwcXrpSign', 'cwcXrpSignLarge', 'cwcXrpAddress', 'ed25519Sign', 'ed25519SignLarge']) {
      const method = addon[name];
      assert.equal(typeof method, 'function', 'Rebuild the wallet crypto addon for ' + name);
      counts.set(name, 0);
      addon[name] = (...args) => {
        counts.set(name, counts.get(name) + 1);
        return method(...args);
      };
    }
  }
  const { BitcoreLib, Deriver, Message, Transactions, ethers, xrpl } = require('../packages/crypto-wallet-core');
  const { recoverEvmAddress, signEvmDigest, trySignXrp } = require('../packages/crypto-wallet-core/ts_build/src/wallet-crypto');
  assert.equal(trySignXrp('abcd', 'ed' + '00'.repeat(30)), undefined);
  const results = [];
  const recordError = run => assert.throws(run, err => {
    results.push([err.name, err.code, err.message]);
    return true;
  });

  const privKey = Buffer.alloc(32, 22).toString('hex');
  const key = { privKey, pubKey: new BitcoreLib.PrivateKey(privKey).publicKey.toString() };
  const signer = new ethers.Wallet('0x' + privKey);
  const signingKey = new ethers.SigningKey(signer.privateKey);
  const malformedDigest = ethers.ZeroHash + 'zz';
  recordError(() => recoverEvmAddress(malformedDigest, signingKey.sign(ethers.ZeroHash)));
  for (const digest of [
    '0x' + '00'.repeat(32),
    '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
    '0x' + 'ff'.repeat(32)
  ]) {
    const signature = signEvmDigest(signingKey, digest).serialized;
    assert.equal(signature, signingKey.sign(digest).serialized);
    results.push(signature);
  }
  const recipient = new ethers.Wallet('0x' + '31'.repeat(32)).address;
  const contractAddress = new ethers.Wallet('0x' + '52'.repeat(32)).address;
  const evmChains = ['ETH', 'ARB', 'BASE', 'OP', 'MATIC', 'ARC'];
  const transactionChains = [...evmChains, ...evmChains.map(chain => chain + 'ERC20'), 'ETHMULTISIG', 'MATICMULTISIG'];
  for (const chain of transactionChains) {
    for (const txType of [0, 1, 2]) {
      const raw = Transactions.create({
        chain, recipients: [{ address: recipient, amount: '1000' }], network: 'mainnet',
        multisigContractAddress: contractAddress, tokenAddress: contractAddress, gasPrice: 1e9,
        data: '0x', gasLimit: 90000, nonce: 24, txType,
        maxGasFee: txType === 2 ? 2e9 : undefined, priorityGasFee: 1
      });
      const expected = ethers.Transaction.from(raw);
      const sighash = ethers.keccak256(raw);
      expected.signature = new ethers.SigningKey('0x' + privKey).sign(sighash);
      assert.equal(Transactions.getSighash({ chain, tx: raw }), sighash.slice(2));
      assert.equal(Transactions.getHash({ chain, tx: raw }), null);
      assert.equal(Transactions.getSignature({ chain, tx: raw, key }), expected.signature.serialized);
      const signed = Transactions.sign({ chain, tx: raw, key });
      assert.equal(signed, expected.serialized);
      assert.equal(ethers.Transaction.from(signed).from, signer.address);
      assert.equal(Transactions.getHash({ chain, tx: signed }), expected.hash);
      assert.equal(Transactions.applySignature({ chain, tx: raw, signature: expected.signature.compactSerialized }), signed);
      results.push(signed, expected.hash);
      if (chain === 'ETH') {
        const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
        const { r, s, v, yParity } = expected.signature;
        const invalid = [
          { r: ethers.ZeroHash, s, v },
          { r: ethers.toBeHex(order, 32), s, v },
          { r, s: ethers.ZeroHash, v },
          { r, s: ethers.toBeHex(order - BigInt(s), 32), v: 55 - v }
        ];
        for (const signature of invalid) {
          recordError(() => Transactions.applySignature({ chain, tx: raw, signature }));
          const encoded = signature.r + signature.s.slice(2) + ethers.toBeHex(signature.v, 1).slice(2);
          recordError(() => Transactions.applySignature({ chain, tx: raw, signature: encoded }));
        }
        if (txType === 0) {
          const differentChainV = Number(2n * (expected.chainId + 1n) + 35n) + yParity;
          recordError(() => Transactions.applySignature({ chain, tx: raw, signature: { r, s, v: differentChainV } }));
          const encoded = r + s.slice(2) + ethers.toBeHex(differentChainV, 1).slice(2);
          assert.equal(Transactions.applySignature({ chain, tx: raw, signature: encoded }), signed);
        }
      }
      if (txType === 0) {
        recordError(() => Transactions.applySignature({ chain, tx: raw, signature: '0x' }));
        recordError(() => Transactions.getSignature({ chain, tx: raw, key: { privKey: '0x12' } }));
      }
    }
  }
  for (const chain of [...evmChains, 'XRP', 'SOL']) {
    for (const message of ['a plain CWC ledger message', 'é 🎸', 'x'.repeat(5000)]) {
      const digest = ethers.keccak256(ethers.toUtf8Bytes('\x19Ethereum Signed Message:\n' + message.length + message));
      const expected = new ethers.SigningKey('0x' + privKey).sign(digest);
      assert.equal(Message.getMessageHash({ chain, message }).toString('hex'), digest.slice(2));
      const signed = Message.signMessage({ chain, message, encoding: 'hex', privateKey: privKey });
      assert.equal(signed.signature, expected.serialized.slice(2));
      assert.equal(ethers.recoverAddress(digest, '0x' + signed.signature), signer.address);
      results.push(signed);
    }
    if (evmChains.includes(chain)) assert.equal(Deriver.getAddress(chain, 'mainnet', key.pubKey), signer.address);
  }

  const xrpSec = new xrpl.Wallet(key.pubKey, key.privKey);
  const xrpEd = xrpl.Wallet.fromEntropy(Uint8Array.from({ length: 16 }, (_, i) => i + 1));
  const edPrefixedRawSecp = 'ed' + '00'.repeat(31);
  const xrpRawEdPrefix = new xrpl.Wallet(new BitcoreLib.PrivateKey(edPrefixedRawSecp).publicKey.toString(), edPrefixedRawSecp);
  const edPrefixedRaw = xrpl.encode({
    TransactionType: 'Payment', Account: xrpRawEdPrefix.classicAddress, Destination: xrpEd.classicAddress,
    Amount: '10', Fee: '12', Sequence: 1
  });
  const rawEdSigned = Transactions.sign({
    chain: 'XRP', tx: edPrefixedRaw, key: { privKey: edPrefixedRawSecp, pubKey: xrpRawEdPrefix.publicKey }
  });
  assert.equal(rawEdSigned, xrpRawEdPrefix.sign(xrpl.decode(edPrefixedRaw)).tx_blob);
  assert(xrpRawEdPrefix.verifyTransaction(rawEdSigned));
  results.push(rawEdSigned);
  for (const wallet of [xrpSec, xrpEd]) {
    const xrpKey = { pubKey: wallet.publicKey.toLowerCase(), privKey: wallet.privateKey.toLowerCase() };
    const provider = Transactions.get({ chain: 'XRP' });
    const destination = wallet === xrpSec ? xrpEd.classicAddress : xrpSec.classicAddress;
    const payment = {
      TransactionType: 'Payment', Account: wallet.classicAddress, Destination: destination,
      Amount: '10000', Fee: '12', Sequence: 1, Flags: 2147483648
    };
    const ticket = { ...payment, Sequence: 0, TicketSequence: 16 };
    const amount = { currency: 'USD', issuer: destination, value: '123.400' };
    const issued = { ...payment, Amount: amount };
    const issuedTiny = { ...ticket, Amount: { ...amount, value: '1.23e-80' }, SendMax: amount };
    const accountSet = { TransactionType: 'AccountSet', Account: wallet.classicAddress, Fee: '12', Sequence: 2, SetFlag: 1 };
    const accountDelete = {
      TransactionType: 'AccountDelete', Account: wallet.classicAddress, Fee: '2000000',
      Sequence: 2, Destination: destination, DestinationTag: 4
    };
    const trustSet = { TransactionType: 'TrustSet', Account: wallet.classicAddress, Fee: '12', Sequence: 2, LimitAmount: amount };
    const offerCreate = {
      TransactionType: 'OfferCreate', Account: wallet.classicAddress, Fee: '12', Sequence: 2,
      TakerPays: amount, TakerGets: '1000'
    };
    const method = wallet === xrpEd ? 'ed25519Sign' : 'cwcXrpSign';
    for (const transaction of [payment, ticket, issued, issuedTiny, accountSet, accountDelete, trustSet, offerCreate]) {
      const raw = xrpl.encode(transaction);
      const decoded = xrpl.decode(raw);
      const expected = wallet.sign(decoded);
      const signingData = xrpl.encodeForSigning({ ...decoded, SigningPubKey: xrpKey.pubKey });
      const digest = createHash('sha512').update(Buffer.from(signingData, 'hex')).digest('hex').slice(0, 64).toUpperCase();
      assert.equal(Transactions.getSighash({ chain: 'XRP', tx: raw, pubKey: xrpKey.pubKey }), digest);
      const callsBefore = counts.get(method);
      const result = provider.getSignatureObject({ tx: raw, key: xrpKey });
      assert.deepEqual(result, { signedTransaction: expected.tx_blob, hash: expected.hash });
      const signed = Transactions.sign({ chain: 'XRP', tx: raw, key: xrpKey });
      assert.equal(signed, expected.tx_blob);
      assert.equal(Transactions.getHash({ chain: 'XRP', tx: signed }), expected.hash);
      assert(wallet.verifyTransaction(signed));
      assert.equal(Transactions.getSignature({ chain: 'XRP', tx: raw, key: xrpKey }),
        xrpl.decode(expected.tx_blob).TxnSignature);
      if (callsBefore !== undefined) assert.equal(counts.get(method) - callsBefore, 3, transaction.TransactionType);
      results.push(result);
    }
    const signedPayment = wallet.sign(payment);
    const rawPayment = xrpl.encode(payment);
    for (const method of ['getSignatureObject', 'getSignature', 'applySignature']) {
      const withOverride = Object.create(provider);
      let overriddenCalls = 0;
      withOverride[method] = function(params) {
        overriddenCalls++;
        return provider[method].call(this, params);
      };
      assert.equal(withOverride.sign({ tx: rawPayment, key: xrpKey }), signedPayment.tx_blob);
      assert.equal(overriddenCalls, 1, method);
    }

    const callsBeforeFallbacks = counts.get(method);
    recordError(() => provider.getSignatureObject({ tx: signedPayment.tx_blob, key: xrpKey }));
    recordError(() => provider.getSignatureObject({ tx: xrpl.encode({ ...payment, Amount: undefined }), key: xrpKey }));
    const invalidCurrency = xrpl.encode({ ...issued, Amount: { ...amount, currency: 'xRp' } });
    recordError(() => provider.getSignatureObject({ tx: invalidCurrency, key: xrpKey }));
    const multi = wallet.sign(payment, true);
    assert.equal(Transactions.getHash({ chain: 'XRP', tx: multi.tx_blob }), multi.hash);
    recordError(() => provider.getSignatureObject({ tx: multi.tx_blob, key: xrpKey }));
    assert.equal(counts.get(method), callsBeforeFallbacks);
    const longPayment = { ...issued, Memos: [{ Memo: { MemoData: 'AB'.repeat(wallet === xrpEd ? 1500 : 4200) } }] };
    const longRaw = xrpl.encode(longPayment);
    const longExpected = wallet.sign(xrpl.decode(longRaw));
    const largeMethod = method + 'Large';
    const largeCallsBefore = counts.get(largeMethod);
    assert.equal(Transactions.sign({ chain: 'XRP', tx: longRaw, key: xrpKey }), longExpected.tx_blob);
    assert.equal(counts.get(method), callsBeforeFallbacks);
    if (addon) {
      assert.equal(counts.get(largeMethod) - largeCallsBefore, 1);
      const original = addon[largeMethod];
      try {
        addon[largeMethod] = undefined;
        assert.equal(Transactions.sign({ chain: 'XRP', tx: longRaw, key: xrpKey }), longExpected.tx_blob);
      } finally {
        addon[largeMethod] = original;
      }

      const message = Buffer.from(xrpl.encodeForSigning({ ...xrpl.decode(longRaw), SigningPubKey: xrpKey.pubKey }), 'hex');
      const secret = Buffer.from(xrpKey.privKey.slice(-64), 'hex');
      const sign = input => wallet === xrpEd ? original(secret, input).subarray(32) : original(input, secret);
      const padded = Buffer.concat([Buffer.alloc(1), message, Buffer.alloc(1)]);
      assert.equal(sign(padded.subarray(1, -1)).toString('hex').toUpperCase(), xrpl.decode(longExpected.tx_blob).TxnSignature);
      assert.throws(() => sign(new Uint8Array(new SharedArrayBuffer(message.length))), /unshared ArrayBuffer/);
      assert.throws(() => sign(new Uint16Array(message.length)), /unshared ArrayBuffer/);
      assert.throws(() => wallet === xrpEd ? original(secret.subarray(1), message) : original(message, secret.subarray(1)),
        /Expected a 32-byte/);
      if (wallet === xrpSec) assert.equal(original(message, Buffer.alloc(32)), null);
    }
    assert.equal(Deriver.getAddress('XRP', 'mainnet', xrpKey.pubKey), wallet.classicAddress);
    const oddPublicKey = '12';
    assert.equal(Deriver.getAddress('XRP', 'mainnet', oddPublicKey), xrpl.deriveAddress(oddPublicKey));
    recordError(() => Deriver.getAddress('XRP', 'mainnet', 'not-a-key'));
    results.push(multi.hash, longExpected.hash);
  }
  for (const [name, count] of counts) assert(count > 0, 'Public API did not use ' + name);
  return createHash('sha256').update(JSON.stringify(results)).digest('hex');
}

if (process.argv[2] === '--corpus') {
  process.stdout.write(runCorpus());
} else {
  const run = backend => execFileSync(process.execPath, [__filename, '--corpus'], {
    env: { ...process.env, BITCORE_ECDSA_BACKEND: backend }, encoding: 'utf8'
  });
  assert.equal(run('js'), run('native'));
  console.log('CWC EVM and XRP signatures, addresses, hashes, and errors matched across both backends.');
}
