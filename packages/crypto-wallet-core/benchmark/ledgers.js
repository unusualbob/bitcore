/* eslint @typescript-eslint/no-require-imports: "off" -- Standalone CommonJS benchmark. */
'use strict';

const assert = require('node:assert/strict');
const benchmark = require('../../bitcore-lib/benchmark/backends');

benchmark(__filename, ({ BitcoreLib, Deriver, Message, Transactions, ethers, xrpl }) => {
  const recipient = new ethers.Wallet('0x' + '31'.repeat(32)).address;
  const contract = new ethers.Wallet('0x' + '52'.repeat(32)).address;
  const xrpDestination = xrpl.Wallet.fromEntropy(new Uint8Array(16).fill(99)).classicAddress;
  const data = Transactions.get({ chain: 'ETHMULTISIG' }).submitEncodeData({
    recipients: [{ address: recipient, amount: '1000' }], multisigContractAddress: contract, data: '0x'
  });
  const fixtures = Array.from({ length: 8 }, (_, i) => {
    const privKey = Buffer.alloc(32, i + 21).toString('hex');
    const pubKey = new BitcoreLib.PrivateKey(privKey).publicKey.toString();
    const key = { privKey, pubKey };
    const evm = {
      chain: 'ETH', key, tx: Transactions.create({
        chain: 'ETH', network: 'mainnet', nonce: i + 1,
        recipients: [{ address: recipient, amount: '1000' }], gasLimit: 21000, maxGasFee: 2e9, priorityGasFee: 1
      })
    };
    const erc = {
      chain: 'ARBERC20', key, tx: Transactions.create({
        chain: 'ARBERC20', network: 'mainnet', nonce: i + 1, tokenAddress: contract,
        recipients: [{ address: recipient, amount: '1000' }], gasLimit: 90000, maxGasFee: 2e9, priorityGasFee: 1
      })
    };
    const multisig = {
      chain: 'ETHMULTISIG', key, tx: Transactions.create({
        chain: 'ETHMULTISIG', network: 'mainnet', nonce: i + 1, multisigContractAddress: contract,
        data, gasPrice: 1e9, gasLimit: 90000
      })
    };
    const xrpSecp = new xrpl.Wallet(pubKey, privKey);
    const xrpEd = xrpl.Wallet.fromEntropy(new Uint8Array(16).fill(i + 1));
    const xrpParams = wallet => ({
      chain: 'XRP',
      key: { pubKey: wallet.publicKey, privKey: wallet.privateKey },
      tx: xrpl.encode({ TransactionType: 'Payment', Account: wallet.classicAddress,
        Destination: xrpDestination, Amount: '1000', Fee: '12', Sequence: i + 1 })
    });
    const xrp = xrpParams(xrpSecp);
    const xrpEd25519 = xrpParams(xrpEd);
    const signedEvm = { chain: 'ETH', tx: Transactions.sign(evm) };
    const signedXrp = { chain: 'XRP', tx: Transactions.sign(xrp) };
    assert.equal(ethers.Transaction.from(signedEvm.tx).from, new ethers.Wallet('0x' + privKey).address);
    assert(xrpSecp.verifyTransaction(signedXrp.tx));
    assert(xrpEd.verifyTransaction(Transactions.sign(xrpEd25519)));
    return {
      key, evm, erc, multisig, xrp, xrpEd25519, signedEvm, signedXrp,
      message: { chain: 'ETH', message: 'CWC benchmark message ' + String(i).repeat(64), privateKey: privKey },
      apply: { chain: 'ETH', tx: evm.tx, signature: Transactions.getSignature(evm) }
    };
  });

  const operations = {
    evmSign: f => Transactions.sign(f.evm),
    erc20Sign: f => Transactions.sign(f.erc),
    multisigSign: f => Transactions.sign(f.multisig),
    evmApplySignature: f => Transactions.applySignature(f.apply),
    evmHash: f => Transactions.getHash(f.signedEvm),
    evmSighash: f => Transactions.getSighash(f.evm),
    evmMessageSign: f => Message.signMessage(f.message),
    evmAddress: f => Deriver.getAddress('ETH', 'mainnet', f.key.pubKey),
    xrpSignSecp256k1: f => Transactions.sign(f.xrp),
    xrpSignEd25519: f => Transactions.sign(f.xrpEd25519),
    xrpHash: f => Transactions.getHash(f.signedXrp),
    xrpAddress: f => Deriver.getAddress('XRP', 'mainnet', f.key.pubKey)
  };
  if (process.env.BITCORE_ECDSA_BACKEND === 'native') {
    const addon = require('../../bitcore-lib/lib/native/bitcore_ecdsa.node');
    const expected = {
      evmSign: 'cwcSignRecoverable', erc20Sign: 'cwcSignRecoverable', multisigSign: 'cwcSignRecoverable',
      evmApplySignature: 'cwcEvmRecoverAddress', evmHash: 'cwcKeccak256', evmSighash: 'cwcKeccak256',
      evmMessageSign: 'cwcSignRecoverable', evmAddress: 'cwcEvmAddress',
      xrpSignSecp256k1: 'cwcXrpSign', xrpSignEd25519: 'ed25519Sign', xrpAddress: 'cwcXrpAddress'
    };
    for (const [operation, method] of Object.entries(expected)) {
      const original = addon[method];
      assert.equal(typeof original, 'function', 'Rebuild the addon to exercise ' + method);
      let called = false;
      addon[method] = (...args) => {
        called = true;
        return original(...args);
      };
      try {
        operations[operation](fixtures[0]);
        assert(called, operation + ' did not use the native wallet binding');
      } finally {
        addon[method] = original;
      }
    }
  }
  return { fixtures, operations };
}, { load: () => require('..'), warmupMs: 100, sampleMs: 300 });
