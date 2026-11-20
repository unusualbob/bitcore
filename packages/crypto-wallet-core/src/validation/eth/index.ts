import { isEvmAddress } from '../../utils/evm-address';
import type { IValidation } from '../../types/validation';

export class EthValidation implements IValidation {
  regex: RegExp;

  constructor() {
    this.regex = /ethereum/i;
  }

  validateAddress(_network: string, address: string): boolean {
    return isEvmAddress(address);
  }

  validateUri(addressUri: string): boolean {
    if (!addressUri) {
      return false;
    }
    const address = this.extractAddress(addressUri);
    const prefix = this.regex.exec(addressUri);
    return !!prefix && isEvmAddress(address);
  }

  protected extractAddress(data) {
    const prefix = /^[a-z]+:/i;
    const params = /([?&](value|gas|gasPrice|gasLimit)=(\d+([,.]\d+)?))+/i;
    return data.replace(prefix, '').replace(params, '');
  }
}
