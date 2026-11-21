import Web3 from 'web3';
import { AbiItem } from 'web3-utils';
import { ETHTxProvider, prepareMultiSendCall } from '../eth';
import { createContractEncoder } from '../evm-contract';
import { ERC20Abi } from './abi';

export class ERC20TxProvider extends ETHTxProvider {
  getERC20Contract(tokenContractAddress: string) {
    const web3 = new Web3();
    const contract = new web3.eth.Contract(ERC20Abi as AbiItem[], tokenContractAddress);
    return contract;
  }

  create(params: {
    recipients: Array<{ address: string; amount: string }>;
    nonce: number;
    gasPrice?: number;
    data: string;
    gasLimit: number;
    tokenAddress: string;
    network: string;
    chainId?: number;
    contractAddress?: string;
    maxGasFee?: number;
    priorityGasFee?: number;
  }) {
    const { tokenAddress, contractAddress } = params;
    const data = this.encodeData(params);
    const recipients = [{ address: contractAddress || tokenAddress, amount: '0' }];
    const newParams = { ...params, recipients, data };
    return super.create(newParams);
  }

  encodeData(params: {
    recipients: Array<{ address: string; amount: string }>;
    tokenAddress: string;
    contractAddress?: string;
  }) {
    const { tokenAddress, recipients, contractAddress } = params;
    if (recipients.length > 1) {
      const addresses = [];
      const amounts = [];
      for (const recipient of recipients) {
        addresses.push(recipient.address);
        amounts.push(BigInt(recipient.amount));
      }
      return prepareMultiSendCall(this, contractAddress)('sendErc20', tokenAddress, addresses, amounts);
    } else {
      const [{ address, amount }] = params.recipients;
      const amountBI = BigInt(amount);
      const encode = erc20Encoder(this, this.getERC20Contract, tokenAddress);
      return encode('transfer', address, amountBI);
    }
  }
}

const erc20Encoder = createContractEncoder(ERC20Abi as AbiItem[], ERC20TxProvider.prototype.getERC20Contract);
