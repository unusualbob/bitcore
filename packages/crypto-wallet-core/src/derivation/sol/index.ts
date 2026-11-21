import { HDPrivateKey, Networks, PrivateKey, crypto, encoding } from '@bitpay-labs/bitcore-lib';
import * as ed25519 from 'ed25519-hd-key';
import { nativeEd25519PublicKey, nativeSlip10Path } from '../../ed25519';
import { Paths } from '../paths';
import type { IDeriver, Key } from '../../types/derivation';

function publicKeyFromSeed(seed: Buffer): Buffer {
  return nativeEd25519PublicKey(seed) ?? ed25519.getPublicKey(seed, false);
}

const MAX_SERIALIZED_ROOT_LENGTH = Math.ceil(HDPrivateKey.SerializedByteSize * Math.log(256) / Math.log(58));

function readSerializedRoot(xprivKey: string): { key: Buffer; chainCode: Buffer } | undefined {
  if (typeof xprivKey !== 'string' || !xprivKey || xprivKey.length > MAX_SERIALIZED_ROOT_LENGTH || Networks.get(xprivKey)) return;

  let payload: Buffer;
  try {
    payload = encoding.Base58Check.decode(xprivKey);
  } catch {
    // Let HDPrivateKey handle other recognized formats and report its usual errors.
    return;
  }
  if (payload.length !== HDPrivateKey.DataLength) return;

  // Match HDPrivateKey's scalar and network validation without building a secp256k1 public key.
  const key = payload.subarray(HDPrivateKey.PrivateKeyStart, HDPrivateKey.PrivateKeyEnd);
  const network = Networks.get(payload.readInt32BE(HDPrivateKey.VersionStart));
  const error = PrivateKey.getValidationError(crypto.BN.fromBuffer(key), network);
  if (error) throw error;
  return { key, chainCode: payload.subarray(HDPrivateKey.ChainCodeStart, HDPrivateKey.ChainCodeEnd) };
}

export class SolDeriver implements IDeriver {
  deriveAddress(_network, _xpubkey, _addressIndex, _isChange): string {
    throw new Error('Cannot derive Solana addresses from just xpubkey, need to use derivePrivateKeyWithPath');
  }

  deriveAddressWithPath(_network: string, _xpubKey: string, _path: string): string {
    throw new Error('Cannot derive Solana addresses from just xpubkey, need to use derivePrivateKeyWithPath');
  }

  getAddress(_network: string, pubKey: string) {
    return this.addressFromPublicKeyBuffer(Buffer.from(pubKey, 'hex'));
  }

  getPublicKey(_network: string, privKey: Buffer): string {
    if (!Buffer.isBuffer(privKey)) {
      throw new Error('Expected privKey to be a Buffer');
    }
    const pubKey = publicKeyFromSeed(privKey);
    return Buffer.from(pubKey).toString('hex');
  }

  addressFromPublicKeyBuffer(pubKey: Buffer): string {
    if (pubKey.length > 32) {
      pubKey = pubKey.subarray(pubKey.length - 32);
    }
    return encoding.Base58.encode(pubKey);
  }

  derivePrivateKey(network, xPriv, addressIndex, isChange, addressType) {
    const changeNum = isChange ? 1 : 0;
    const path = `${Paths['SOL'].default}${addressIndex}'/${changeNum}'`;
    return this.derivePrivateKeyWithPath(network, xPriv, path, addressType);
  };

  deriveChild(masterKey: { key: Buffer; chainCode: Buffer }, path: string) {
    const HARDENED_OFFSET = 0x80000000;
    const segmented = path
      .split('/')
      .slice(1)
      .map((val) => val.replace("'", ''))
      .map(el => parseInt(el, 10) + HARDENED_OFFSET);
    const nativeChild = segmented.length && nativeSlip10Path(masterKey.key, masterKey.chainCode, segmented);
    return nativeChild || segmented.reduce((parentKeys, index) => ed25519.CKDPriv(parentKeys, index), masterKey);
  }

  derivePrivateKeyWithPath(network: string, xprivKey: string, path: string, _addressType: string) {
    let root = readSerializedRoot(xprivKey);
    if (!root) {
      const xpriv = new HDPrivateKey(xprivKey, network);
      root = { key: xpriv._buffers.privateKey, chainCode: xpriv._buffers.chainCode };
    }
    const child = this.deriveChild(root, path);
    const pubKey = publicKeyFromSeed(child.key);
    const address = encoding.Base58.encode(pubKey);
    // Solana wallets often represent the private key as a KeyPair consisting of the private key + address/public key.
    // The Keypair is usually found in two formats: Base58 or Uint8Array.
    // Here, we represent the keys separately in Base58, which is fine since a keypair can be built or converted by createKeyPairFromPrivateKeyBytes.
    // Public Key is synonymous with Address. Here they are reprsented in two different formats. 
    return {
      address,
      privKey: encoding.Base58.encode(child.key),
      pubKey: Buffer.from(pubKey).toString('hex')
    } as Key;
  };

  /**
   * @param {Buffer | string} privKey - expects base 58 encoded string
   * @returns {Buffer}
   * @throws {Error} If privKey is not a Buffer (planned forwards compatibility) or string. Propagates all other errors
   */
  privateKeyToBuffer(privKey: Buffer | string): Buffer {
    if (Buffer.isBuffer(privKey)) return privKey;
    if (typeof privKey !== 'string') throw new Error(`Expected string, got ${typeof privKey}`);
    // Expects to match return from derivePrivateKey's privKey.
    return encoding.Base58.decode(privKey);
  }

  bufferToPrivateKey_TEMP(buf: Buffer, _network: string): string {
    return encoding.Base58.encode(buf);
  }
}
