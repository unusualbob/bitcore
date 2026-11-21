import Web3 from 'web3';
import { AbiItem } from 'web3-utils';
import { ETHTxProvider } from '../eth';
import { createContractEncoder } from '../evm-contract';
import { MultisigAbi } from './abi';

export class ETHMULTISIGTxProvider extends ETHTxProvider {
  getMultisigContract(multisigContractAddress: string) {
    const web3 = new Web3();
    const contract = new web3.eth.Contract(MultisigAbi as AbiItem[], multisigContractAddress);
    return contract;
  }

  create(params: {
    recipients: Array<{ address: string; amount: string }>;
    nonce: number;
    gasPrice: number;
    data: string;
    gasLimit: number;
    multisigContractAddress: string;
    network: string;
    chainId?: number;
  }) {
    const { multisigContractAddress } = params;
    const recipients = [{ address: multisigContractAddress, amount: '0' }];
    const newParams = { ...params, recipients };
    return super.create(newParams);
  }

  instantiateEncodeData(params: {
    addresses: Array<string>;
    requiredConfirmations: number;
    multisigGnosisContractAddress: string;
    dailyLimit: number;
  }) {
    const { addresses, requiredConfirmations, multisigGnosisContractAddress, dailyLimit } = params;
    const requiredConfirmationsStr = Number(requiredConfirmations).toLocaleString('en', { useGrouping: false });
    const dailyLimitStr = Number(dailyLimit).toLocaleString('en', { useGrouping: false });
    const encode = multisigEncoder(this, this.getMultisigContract, multisigGnosisContractAddress);
    const data = encode('create', addresses, requiredConfirmationsStr, dailyLimitStr);
    return data;
  }

  addOwnerEncodeData(params: { newOwnerAddress: string; multisigContractAddress: string }) {
    const { multisigContractAddress, newOwnerAddress } = params;
    const encode = multisigEncoder(this, this.getMultisigContract, multisigContractAddress);
    const data = encode('addOwner', newOwnerAddress);
    return this.submitEncodeData({
      recipients: [
        {
          address: multisigContractAddress,
          amount: '0'
        }
      ],
      multisigContractAddress,
      data
    });
  }

  removeOwnerEncodeData(params: { newOwnerAddress: string; multisigContractAddress: string }) {
    const { multisigContractAddress, newOwnerAddress } = params;
    const encode = multisigEncoder(this, this.getMultisigContract, multisigContractAddress);
    const data = encode('removeOwner', newOwnerAddress);
    return this.submitEncodeData({
      recipients: [
        {
          address: multisigContractAddress,
          amount: '0'
        }
      ],
      multisigContractAddress,
      data
    });
  }

  replaceOwnerEncodeData(params: {
    oldOwnerAddress: string;
    newOwnerAddress: string;
    multisigContractAddress: string;
  }) {
    const { multisigContractAddress, newOwnerAddress, oldOwnerAddress } = params;
    const encode = multisigEncoder(this, this.getMultisigContract, multisigContractAddress);
    const data = encode('removeOwner', oldOwnerAddress, newOwnerAddress);
    return this.submitEncodeData({
      recipients: [
        {
          address: multisigContractAddress,
          amount: '0'
        }
      ],
      multisigContractAddress,
      data
    });
  }

  changeRequirementEncodedData(params: { requiredConfirmations: number; multisigContractAddress: string }) {
    const { requiredConfirmations, multisigContractAddress } = params;
    const requiredConfirmationsStr = Number(requiredConfirmations).toLocaleString('en', { useGrouping: false });
    const encode = multisigEncoder(this, this.getMultisigContract, multisigContractAddress);
    const data = encode('changeRequirement', requiredConfirmationsStr);
    return this.submitEncodeData({
      recipients: [
        {
          address: multisigContractAddress,
          amount: '0'
        }
      ],
      multisigContractAddress,
      data
    });
  }

  changeDailyLimitEncodedData(params: { requiredConfirmations: number; multisigContractAddress: string }) {
    const { requiredConfirmations, multisigContractAddress } = params;
    const requiredConfirmationsStr = Number(requiredConfirmations).toLocaleString('en', { useGrouping: false });
    const encode = multisigEncoder(this, this.getMultisigContract, multisigContractAddress);
    const data = encode('changeDailyLimit', requiredConfirmationsStr);
    return this.submitEncodeData({
      recipients: [
        {
          address: multisigContractAddress,
          amount: '0'
        }
      ],
      multisigContractAddress,
      data
    });
  }

  confirmTransactionEncodeData(params: { multisigContractAddress: string; transactionId: number }) {
    const { multisigContractAddress, transactionId } = params;
    const encode = multisigEncoder(this, this.getMultisigContract, multisigContractAddress);
    const data = encode('confirmTransaction', transactionId);
    return data;
  }

  revokeConfirmationEncodeData(params: { multisigContractAddress: string; transactionId: number }) {
    const { multisigContractAddress, transactionId } = params;
    const encode = multisigEncoder(this, this.getMultisigContract, multisigContractAddress);
    const data = encode('revokeConfirmation', transactionId);
    return data;
  }

  executeTransactionEncodeData(params: { multisigContractAddress: string; transactionId: number }) {
    const { multisigContractAddress, transactionId } = params;
    const encode = multisigEncoder(this, this.getMultisigContract, multisigContractAddress);
    const data = encode('executeTransaction', transactionId);
    return data;
  }

  // data: It is used to invoke functionalities of a contract and can be left empty ('0x') or bytes(0) for regular value transfers.
  // address: It is used o invoke functionalities of a contract needs to be the address of the Smart Contract whose method you want to invoke.
  submitEncodeData(params: {
    recipients: Array<{ address: string; amount: string }>;
    multisigContractAddress: string;
    data: string;
  }) {
    const { multisigContractAddress, data } = params;
    const [{ address, amount }] = params.recipients;
    const amountStr = Number(amount).toLocaleString('en', { useGrouping: false });
    const encode = multisigEncoder(this, this.getMultisigContract, multisigContractAddress);
    return encode('submitTransaction', address, amountStr, data);
  }
}

const multisigEncoder = createContractEncoder(MultisigAbi as AbiItem[], ETHMULTISIGTxProvider.prototype.getMultisigContract);
