import { utils } from 'web3';
import { nativeCrypto } from '../native';

function addressBody(address: string): Buffer | undefined {
  if (typeof address !== 'string') return;
  const body = address.length === 42 && /^0x/i.test(address) ? address.slice(2) : address;
  if (body.length === 40 && Buffer.byteLength(body) === 40) return Buffer.from(body);
}

export function isEvmAddress(address: string): boolean {
  if (typeof nativeCrypto?.cwcEvmValidAddress === 'function') {
    const bytes = addressBody(address);
    if (bytes) return nativeCrypto.cwcEvmValidAddress(bytes);
  }
  return utils.isAddress(address);
}

export function toChecksumAddress(address: string): string {
  if (typeof nativeCrypto?.cwcChecksumAddress === 'function') {
    const bytes = addressBody(address);
    const result = bytes && nativeCrypto.cwcChecksumAddress(bytes);
    if (result) return result.toString('ascii');
  }
  return utils.toChecksumAddress(address);
}
