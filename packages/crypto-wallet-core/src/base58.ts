import { encoding } from '@bitpay-labs/bitcore-lib';
import * as SolKit from '@solana/kit';

export function encodeBase58(bytes: Uint8Array): string {
  if (bytes instanceof Uint8Array && bytes.length >= 32 && bytes.length <= 64 &&
      bytes.buffer instanceof ArrayBuffer) {
    const view = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return encoding.Base58.encode(view);
  }
  return SolKit.getBase58Decoder().decode(bytes);
}

export function decodeBase58(value: string): Uint8Array {
  if (typeof value === 'string' && value.length >= 32 && value.length <= 88) {
    try {
      const bytes = encoding.Base58.decode(value);
      return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    } catch {
      // Let Solana Kit report its usual errors for malformed text.
    }
  }
  return SolKit.getBase58Encoder().encode(value) as Uint8Array;
}
