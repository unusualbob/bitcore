import assert from 'node:assert/strict';
import Web3 from 'web3';
import type { AbiItem } from 'web3-utils';
import { ETHTxProvider } from '../src/transactions/eth';
import { ERC20TxProvider } from '../src/transactions/erc20';
import { ETHMULTISIGTxProvider } from '../src/transactions/eth-multisig';
import { MATICMULTISIGTxProvider } from '../src/transactions/matic-multisig';
import { ERC20Abi, MULTISENDAbi } from '../src/transactions/erc20/abi';
import { MultisigAbi } from '../src/transactions/eth-multisig/abi';

const tokenAddress = '0x00000000000000000000000000000000000000ab';
const contractAddress = '0x00000000000000000000000000000000000000cd';
const recipients = [
  { address: '0x00000000000000000000000000000000000000ef', amount: '1000000000000000000' },
  { address: '0x0000000000000000000000000000000000000012', amount: '0' }
];
const txParams = { nonce: 0, gasPrice: 10, gasLimit: 150000, network: 'mainnet', data: '', contractAddress };

function freshContract(abi: AbiItem[], address: string) {
  const web3 = new Web3();
  return new web3.eth.Contract(abi, address);
}

function errorFrom(operation: () => unknown) {
  try {
    operation();
  } catch (error) {
    return { name: error.name, code: error.code, message: error.message };
  }
  assert.fail('Expected the operation to throw');
}

describe('EVM contract transaction encoding', () => {
  it('matches Web3 for ETH multisend and honors supplied calldata', () => {
    const provider = new ETHTxProvider();
    const fresh = new ETHTxProvider();
    fresh.getMultiSendContract = address => freshContract(MULTISENDAbi as AbiItem[], address);
    assert.equal(provider.create({ ...txParams, recipients }), fresh.create({ ...txParams, recipients }));
    const withData = { ...txParams, recipients: [{ ...recipients[0], address: 'invalid' }, recipients[1]], data: '0x1234' };
    assert.equal(provider.create(withData), fresh.create(withData));
    for (const data of ['', '0x1234']) {
      const invalid = { ...txParams, recipients, contractAddress: 'invalid', data };
      assert.deepEqual(errorFrom(() => provider.create(invalid)), errorFrom(() => fresh.create(invalid)));
    }
  });

  it('matches Web3 for ERC20 transfer, multisend, optional addresses and invalid inputs', () => {
    const provider = new ERC20TxProvider();
    const fresh = new ERC20TxProvider();
    fresh.getERC20Contract = address => freshContract(ERC20Abi as AbiItem[], address);
    fresh.getMultiSendContract = address => freshContract(MULTISENDAbi as AbiItem[], address);
    for (const params of [
      { tokenAddress, recipients: recipients.slice(0, 1) },
      { tokenAddress: tokenAddress.slice(2), recipients: recipients.slice(0, 1) },
      { tokenAddress: '', recipients: recipients.slice(0, 1) },
      { tokenAddress, recipients, contractAddress },
      { tokenAddress, recipients }
    ]) {
      assert.equal(provider.encodeData(params), fresh.encodeData(params));
    }
    for (const params of [
      { tokenAddress: 'invalid', recipients: recipients.slice(0, 1) },
      { tokenAddress, recipients: [{ ...recipients[0], amount: '-1' }] },
      { tokenAddress, recipients: [{ ...recipients[0], amount: (2n ** 256n).toString() }] },
      { tokenAddress, recipients: [{ ...recipients[0], address: 'invalid' }, recipients[1]], contractAddress }
    ]) {
      assert.deepEqual(errorFrom(() => provider.encodeData(params)), errorFrom(() => fresh.encodeData(params)));
    }
  });

  it('matches fresh Web3 contracts for ETH and Polygon multisig calldata', () => {
    for (const Provider of [ETHMULTISIGTxProvider, MATICMULTISIGTxProvider]) {
      const provider = new Provider();
      const fresh = new Provider();
      fresh.getMultisigContract = address => freshContract(MultisigAbi as AbiItem[], address);
      const owner = { multisigContractAddress: contractAddress, newOwnerAddress: recipients[0].address };
      const transaction = { multisigContractAddress: contractAddress, transactionId: 7 };
      const limit = { multisigContractAddress: contractAddress, requiredConfirmations: 2 };
      const cases = [
        (p: typeof provider) => p.instantiateEncodeData({
          addresses: recipients.map(r => r.address), requiredConfirmations: 2, dailyLimit: 100,
          multisigGnosisContractAddress: contractAddress
        }),
        (p: typeof provider) => p.addOwnerEncodeData(owner),
        (p: typeof provider) => p.removeOwnerEncodeData(owner),
        (p: typeof provider) => p.replaceOwnerEncodeData({ ...owner, oldOwnerAddress: recipients[1].address }),
        (p: typeof provider) => p.changeRequirementEncodedData(limit),
        (p: typeof provider) => p.changeDailyLimitEncodedData(limit),
        (p: typeof provider) => p.confirmTransactionEncodeData(transaction),
        (p: typeof provider) => p.revokeConfirmationEncodeData(transaction),
        (p: typeof provider) => p.executeTransactionEncodeData(transaction),
        (p: typeof provider) => p.submitEncodeData({ ...owner, recipients, data: '0x1234' })
      ];
      for (const encode of cases) assert.equal(encode(provider), encode(fresh));
      const invalid = { ...transaction, transactionId: -1 };
      assert.deepEqual(
        errorFrom(() => provider.confirmTransactionEncodeData(invalid)),
        errorFrom(() => fresh.confirmTransactionEncodeData(invalid))
      );
    }
  });

  it('returns fresh mutable contracts and observes shared ABI edits after warming the encoder', () => {
    const provider = new ERC20TxProvider();
    const params = { tokenAddress, recipients: recipients.slice(0, 1) };
    const expected = freshContract(ERC20Abi as AbiItem[], tokenAddress).methods
      .transfer(recipients[0].address, BigInt(recipients[0].amount)).encodeABI();
    const first = provider.getERC20Contract(tokenAddress);
    const second = provider.getERC20Contract(tokenAddress);
    assert.notEqual(first, second);
    assert.equal(provider.encodeData(params), expected);
    first.options.address = contractAddress;
    assert(Reflect.set(first.options, 'gas', '1000'));
    assert.notEqual(first.options.address, second.options.address);
    assert.equal(second.options.gas, undefined);

    const transfer = first.options.jsonInterface.find(fragment => 'name' in fragment && fragment.name === 'transfer');
    const input = transfer.inputs[0];
    const originalType = input.type;
    try {
      assert(Reflect.set(input, 'type', 'bytes20'));
      const modified = provider.getERC20Contract(tokenAddress).methods
        .transfer(recipients[0].address, BigInt(recipients[0].amount)).encodeABI();
      assert.notEqual(modified, expected);
      assert.equal(provider.encodeData(params), modified);
    } finally {
      Reflect.set(input, 'type', originalType);
    }

    const index = ERC20Abi.findIndex(fragment => fragment.name === 'transfer');
    const original = ERC20Abi[index];
    try {
      assert(Reflect.set(ERC20Abi, index, { ...original, inputs: [{ name: '_to', type: 'bytes20' }, original.inputs[1]] }));
      const modified = provider.getERC20Contract(tokenAddress).methods
        .transfer(recipients[0].address, BigInt(recipients[0].amount)).encodeABI();
      assert.notEqual(modified, expected);
      assert.equal(provider.encodeData(params), modified);
    } finally {
      ERC20Abi[index] = original;
    }

    first.options.jsonInterface = [];
    assert.equal(typeof second.methods.transfer, 'function');
    assert.equal(provider.encodeData(params), expected);
  });

  it('dispatches to replaced getters with the provider as receiver', () => {
    const provider = new ERC20TxProvider();
    const calls: string[] = [];
    provider.getERC20Contract = function(address) {
      assert.equal(this, provider);
      calls.push(address);
      const contract = freshContract(ERC20Abi as AbiItem[], tokenAddress);
      contract.methods.transfer = () => ({ encodeABI: () => '0x1234' }) as ReturnType<typeof contract.methods.transfer>;
      return contract;
    };
    assert.equal(provider.encodeData({ tokenAddress: 'override-only', recipients: recipients.slice(0, 1) }), '0x1234');
    provider.getMultiSendContract = function(address) {
      assert.equal(this, provider);
      calls.push(address);
      return freshContract(MULTISENDAbi as AbiItem[], address);
    };
    ETHTxProvider.prototype.create.call(provider, { ...txParams, recipients, data: '0x1234' });
    assert.deepEqual(calls, ['override-only', contractAddress]);
  });
});
