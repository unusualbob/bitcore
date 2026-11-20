import { Utils, Web3 } from '@bitpay-labs/crypto-wallet-core';
import { LRUCache } from 'lru-cache';

const checksums = new LRUCache<string, string>({ max: 4096 });
type AddressUtils = Pick<typeof Web3.utils, 'toChecksumAddress'>;
const walletUtils = Utils as Partial<AddressUtils>;

export function checksumAddress(address: string, utils: AddressUtils = Web3.utils): string {
  if (utils.toChecksumAddress !== Web3.utils.toChecksumAddress) return utils.toChecksumAddress(address);

  const cached = checksums.get(address);
  if (cached !== undefined) return cached;

  const normalize = walletUtils.toChecksumAddress ?? Web3.utils.toChecksumAddress;
  const checksummed = normalize(address);
  if (typeof address === 'string') checksums.set(address, checksummed);
  return checksummed;
}
