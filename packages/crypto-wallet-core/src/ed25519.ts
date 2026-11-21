import { nativeCrypto } from './native';

// The original binding copies messages up to the Solana network packet size.
const MAX_INLINE_MESSAGE_BYTES = 1232;
const MAX_PATH_DEPTH = 255;

function readResult(result: unknown, bytes: number): Buffer {
  if (!Buffer.isBuffer(result) || result.length !== bytes) {
    throw new Error('Invalid result from native Ed25519');
  }
  return result;
}

function fixedSeed(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array && value.length === 32 && value.buffer instanceof ArrayBuffer;
}

export function nativeEd25519PublicKey(seed: Buffer): Buffer | undefined {
  if (typeof nativeCrypto?.ed25519PublicKey !== 'function' || !fixedSeed(seed)) return;
  return readResult(nativeCrypto.ed25519PublicKey(seed), 32);
}

export function nativeSlip10Path(key: Buffer, chainCode: Buffer, indexes: number[]) {
  if (typeof nativeCrypto?.slip10DeriveEd25519 !== 'function' ||
      !fixedSeed(key) || !fixedSeed(chainCode) || indexes.length === 0 || indexes.length > MAX_PATH_DEPTH ||
      !indexes.every(index => Number.isInteger(index) && index >= 0 && index <= 0xffffffff)) return;

  const path = Buffer.alloc(indexes.length * 4);
  for (const [offset, index] of indexes.entries()) path.writeUInt32BE(index, offset * 4);
  const derived = readResult(nativeCrypto.slip10DeriveEd25519(key, chainCode, path), 64);
  return { key: derived.subarray(0, 32), chainCode: derived.subarray(32) };
}

export function nativeEd25519Sign(seed: unknown, message: unknown) {
  if (!fixedSeed(seed) || !(message instanceof Uint8Array) ||
      message.length === 0 || !(message.buffer instanceof ArrayBuffer)) return;
  const sign = message.length <= MAX_INLINE_MESSAGE_BYTES ? nativeCrypto?.ed25519Sign : nativeCrypto?.ed25519SignLarge;
  if (typeof sign !== 'function') return;
  const signed = readResult(sign(seed, message), 96);
  return { publicKey: signed.subarray(0, 32), signature: signed.subarray(32) };
}
