/* eslint @typescript-eslint/no-require-imports: "off" -- Offline benchmark fixtures. */
'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');

module.exports = function ledgerWorkloads(root) {
  const pkg = name => path.resolve(root, 'packages', name);
  const { BitcoreLib, Transactions, ethers, xrpl } = require(pkg('crypto-wallet-core'));
  const block = BitcoreLib.Block.fromString(require(pkg('bitcore-lib/benchmark/block-357238.json')));
  assert.equal(block.transactions.length, 369);
  const privKey = '15'.repeat(32);
  const pubKey = new BitcoreLib.PrivateKey(privKey).publicKey.toString();
  const key = { pubKey, privKey };
  const recipient = new ethers.Wallet('0x' + '31'.repeat(32)).address;
  const contract = new ethers.Wallet('0x' + '52'.repeat(32)).address;
  const recipients = [{ address: recipient, amount: '1000' }];
  const arb = Transactions.create({ chain: 'ARBERC20', network: 'mainnet', nonce: 1,
    tokenAddress: contract, recipients, gasLimit: 90000, maxGasFee: 2e9, priorityGasFee: 1 });
  const data = Transactions.get({ chain: 'ETHMULTISIG' }).submitEncodeData({
    recipients, multisigContractAddress: contract, data: '0x'
  });
  const eth = Transactions.create({ chain: 'ETHMULTISIG', network: 'mainnet', nonce: 1,
    multisigContractAddress: contract, data, gasPrice: 1e9, gasLimit: 90000 });
  const wallet = new xrpl.Wallet(pubKey, privKey);
  const destination = xrpl.Wallet.fromEntropy(new Uint8Array(16).fill(99)).classicAddress;
  const xrp = xrpl.encode({ TransactionType: 'Payment', Account: wallet.classicAddress,
    Destination: destination, Amount: { currency: 'USD', issuer: destination, value: '1.23' },
    Fee: '12', Sequence: 1 });
  const signEvm = (chain, tx) => ({
    run: () => Transactions.sign({ chain, tx, key }),
    check: signed => {
      assert.equal(ethers.Transaction.from(signed).from, new ethers.Wallet('0x' + privKey).address);
      return signed;
    }
  });
  return {
    'Arbitrum ERC-20 transfer, sign': signEvm('ARBERC20', arb),
    'ETH multisig contract call, sign': signEvm('ETHMULTISIG', eth),
    'XRP issued-currency payment, secp256k1 sign': {
      run: () => Transactions.sign({ chain: 'XRP', tx: xrp, key }),
      check: signed => {
        assert.ok(wallet.verifyTransaction(signed));
        return signed;
      }
    },
    'BTC block 357238, validate Merkle root (369 transactions)': {
      run: () => block.validMerkleRoot(),
      check: valid => {
        assert.equal(valid, true);
        return block.header.merkleRoot.toString('hex');
      }
    }
  };
};
