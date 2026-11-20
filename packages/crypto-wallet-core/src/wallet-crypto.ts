import { createHash } from 'crypto';
import { ethers } from 'ethers';
import { deriveAddress, encodeAccountID } from 'xrpl';
import { nativeEd25519Sign } from './ed25519';
import { nativeCrypto } from './native';

const MAX_NATIVE_INPUT = 4096;
const SEC_PUBLIC_KEY = /^(?:(?:02|03|ed)[0-9a-f]{64}|04[0-9a-f]{128})$/i;
const XRP_ED25519_SECRET = /^ed[0-9a-f]{64}$/i;
const XRP_SECP256K1_SECRET = /^(?:00)?[0-9a-f]{64}$/i;
const HALF_SECP256K1_ORDER = '0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0';

function readResult(result: unknown, length: number): Buffer {
  if (!Buffer.isBuffer(result) || result.length !== length) {
    throw new Error('Invalid result from native wallet cryptography');
  }
  return result;
}

export function evmHash(value: ethers.BytesLike): string {
  if (typeof nativeCrypto?.cwcKeccak256 === 'function') {
    const bytes = ethers.getBytes(value, 'data');
    if (bytes.length > 0 && bytes.length <= MAX_NATIVE_INPUT) {
      return '0x' + readResult(nativeCrypto.cwcKeccak256(Buffer.from(bytes)), 32).toString('hex');
    }
  }
  return ethers.keccak256(value);
}

export function signEvmDigest(signingKey: ethers.SigningKey, digest: string): ethers.Signature {
  if (typeof nativeCrypto?.cwcSignRecoverable === 'function' && /^0x[0-9a-f]{64}$/i.test(digest)) {
    const secret = Buffer.from(signingKey.privateKey.slice(2), 'hex');
    let signature: Buffer | null;
    try {
      signature = nativeCrypto.cwcSignRecoverable(Buffer.from(digest.slice(2), 'hex'), secret);
    } finally {
      secret.fill(0);
    }
    if (signature) {
      readResult(signature, 65);
      return ethers.Signature.from({
        r: '0x' + signature.subarray(0, 32).toString('hex'),
        s: '0x' + signature.subarray(32, 64).toString('hex'),
        v: signature[64] ? 28 : 27
      });
    }
  }
  return signingKey.sign(digest);
}

export function recoverEvmAddress(digest: string, signature: ethers.Signature): string {
  if (typeof nativeCrypto?.cwcEvmRecoverAddress === 'function' && isCanonicalEvmSignature(signature)) {
    const compact = Buffer.from(signature.r.slice(2) + signature.s.slice(2), 'hex');
    const result = nativeCrypto.cwcEvmRecoverAddress(Buffer.from(digest.slice(2), 'hex'), compact, signature.yParity);
    if (result) return readResult(result, 42).toString('ascii');
  }
  return ethers.recoverAddress(digest, signature);
}

export function isCanonicalEvmSignature(signature: ethers.Signature): boolean {
  return signature.s <= HALF_SECP256K1_ORDER;
}

export function sha512Half(hex: string): string {
  return createHash('sha512').update(Buffer.from(hex, 'hex')).digest('hex').toUpperCase().slice(0, 64);
}

export function deriveXrpAddress(publicKey: string): string {
  if (typeof nativeCrypto?.cwcXrpAddress === 'function' &&
      typeof publicKey === 'string' && SEC_PUBLIC_KEY.test(publicKey)) {
    return encodeAccountID(readResult(nativeCrypto.cwcXrpAddress(Buffer.from(publicKey, 'hex')), 20));
  }
  return deriveAddress(publicKey);
}

export function supportsXrpSigning(privateKey: unknown): privateKey is string {
  if (typeof privateKey !== 'string') return false;
  if (XRP_ED25519_SECRET.test(privateKey)) {
    return typeof nativeCrypto?.ed25519Sign === 'function';
  }
  return typeof nativeCrypto?.cwcXrpSign === 'function' && XRP_SECP256K1_SECRET.test(privateKey);
}

export function trySignXrp(encoded: string, privateKey: string): string | undefined {
  if (!supportsXrpSigning(privateKey)) return;
  const bytes = Buffer.from(encoded, 'hex');
  if (bytes.length === 0 || bytes.length > MAX_NATIVE_INPUT) return;
  const secret = Buffer.from(privateKey.slice(-64), 'hex');
  try {
    if (XRP_ED25519_SECRET.test(privateKey)) {
      return nativeEd25519Sign(secret, bytes)?.signature.toString('hex').toUpperCase();
    }
    const signature = nativeCrypto.cwcXrpSign(bytes, secret);
    if (signature) {
      if (!Buffer.isBuffer(signature) || signature.length < 8 || signature.length > 72) {
        throw new Error('Invalid DER signature from native XRP signing');
      }
      return signature.toString('hex').toUpperCase();
    }
  } finally {
    secret.fill(0);
  }
}
