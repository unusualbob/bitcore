import BitcoreLib from '@bitpay-labs/bitcore-lib';
import BitcoreLibCash from '@bitpay-labs/bitcore-lib-cash';
import BitcoreLibDoge from '@bitpay-labs/bitcore-lib-doge';
import BitcoreLibLtc from '@bitpay-labs/bitcore-lib-ltc';
import { loadNativeCrypto, nativeCrypto } from '../native';
import type { IDeriver } from '../types/derivation';

const MAX_CHILDREN = 256;
const HARDENED = 0x80000000;
const SEC_KEY_LENGTH = 33;
const forks = {
  BCH: { lib: BitcoreLibCash, packageName: '@bitpay-labs/bitcore-lib-cash' },
  DOGE: { lib: BitcoreLibDoge },
  LTC: { lib: BitcoreLibLtc, packageName: '@bitpay-labs/bitcore-lib-ltc' }
};

function hdMethods(lib) {
  const { HDPublicKey, HDPrivateKey, PublicKey } = lib;
  const proto = HDPublicKey.prototype;
  return [
    proto.derive, proto.deriveChild, proto._deriveFromString, proto._deriveWithNumber,
    HDPublicKey.isValidPath, HDPrivateKey._getDerivationIndexes,
    PublicKey.fromPoint, PublicKey.prototype.toBuffer
  ];
}

const hdDefinitions = new Map(
  [BitcoreLib, BitcoreLibCash, BitcoreLibDoge, BitcoreLibLtc].map(lib => [
    lib, { HDPublicKey: lib.HDPublicKey, methods: hdMethods(lib) }
  ])
);

export function deriveAddressRange(
  chain: string, deriver: IDeriver, network: string, xpubKey: string, start: number, end: number,
  withChange: boolean, addressType?: string
): string[] | undefined {
  if (typeof xpubKey !== 'string' || !Number.isInteger(start) || !Number.isInteger(end) ||
      start < 0 || start >= end || end > HARDENED) return;

  const fork = forks[chain];
  const lib = fork?.lib ?? BitcoreLib;
  const { HDPublicKey, methods } = hdDefinitions.get(lib);
  if (lib.HDPublicKey !== HDPublicKey || hdMethods(lib).some((method, i) => method !== methods[i])) return;

  const root = new HDPublicKey(xpubKey, network);
  if (root.toString() !== xpubKey) return;
  const paths = withChange ? ['m/0', 'm/1'] : ['m/0'];
  const format = key => deriver.getAddress(network, chain === 'XRP' ? key.toString('hex') : key, addressType);
  const addresses: string[] = [];

  // Full paths preserve both lookup and recency updates in Dogecoin's HD key cache.
  const useFullPaths = chain === 'DOGE';
  const parents = useFullPaths ? [] : paths.map(path => root.derive(path));
  const addon = fork ? fork.packageName && loadNativeCrypto(fork.packageName) : nativeCrypto;
  if (typeof addon?.derivePublicChildren !== 'function') {
    for (let index = start; index < end; index++) {
      for (let branch = 0; branch < paths.length; branch++) {
        const child = useFullPaths ? root.derive(`${paths[branch]}/${index}`) : parents[branch].derive(index);
        addresses.push(format(child.publicKey));
      }
    }
    return addresses;
  }

  const branches = parents.map(branch => {
    return { key: branch.publicKey.toBuffer(), chainCode: Buffer.from(branch.toObject().chainCode, 'hex') };
  });

  for (let index = start; index < end; index += MAX_CHILDREN) {
    const count = Math.min(MAX_CHILDREN, end - index);
    const batches: Array<Buffer | null> = branches.map(({ key, chainCode }) =>
      addon.derivePublicChildren(key, chainCode, index, count)
    );
    if (batches.includes(null)) return; // Rare BIP32 tweak. Defer to scalar derivation.
    const size = SEC_KEY_LENGTH * count;
    if (batches.some(keys => !Buffer.isBuffer(keys) || keys.length !== size)) {
      throw new Error('Invalid native HD child keys');
    }
    for (let offset = 0; offset < size; offset += SEC_KEY_LENGTH) {
      for (const keys of batches) {
        addresses.push(format(keys.subarray(offset, offset + SEC_KEY_LENGTH)));
      }
    }
  }
  return addresses;
}
