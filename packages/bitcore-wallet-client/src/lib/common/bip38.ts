/* eslint no-bitwise: "off" -- BIP38 uses bit flags and bytewise XOR. */
import crypto from 'crypto';
import { BitcoreLib } from '@bitpay-labs/crypto-wallet-core';
import Bip38 from 'bip38';

interface Bip38Instance {
  scryptParams: crypto.ScryptOptions;
  decrypt(encrypted: string, passphrase: string, progressCallback: unknown): string;
  decryptRaw(data: Buffer, passphrase: string, progressCallback: unknown): { privateKey: Buffer; compressed: boolean };
}

const LegacyBip38: new () => Bip38Instance = Bip38;

function xorInPlace(bytes: Buffer, mask: Buffer): Buffer {
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] ^= mask[i];
  }
  return bytes;
}

function decryptBlock(ciphertext: Buffer, key: Buffer): Buffer {
  const decipher = crypto.createDecipheriv('aes-256-ecb', key, Buffer.alloc(0));
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function decryptECMultiply(data: Buffer, password: Buffer, params: crypto.ScryptOptions): Buffer {
  const addressHash = data.subarray(3, 7);
  const ownerEntropy = data.subarray(7, 15);
  const hasLotSequence = (data[2] & 0x04) !== 0;
  const ownerSalt = hasLotSequence ? ownerEntropy.subarray(0, 4) : ownerEntropy;
  const prefactor = crypto.scryptSync(password, ownerSalt, 32, params);
  const { BN, Hash, Point } = BitcoreLib.crypto;
  const passfactor = hasLotSequence ? Hash.sha256sha256(Buffer.concat([prefactor, ownerEntropy])) : prefactor;
  const point = crypto.createECDH('secp256k1');
  point.setPrivateKey(passfactor);
  const passpoint = point.getPublicKey(undefined, 'compressed');
  const derived = crypto.scryptSync(passpoint, Buffer.concat([addressHash, ownerEntropy]), 64, { N: 1024, r: 1, p: 1 });
  const key = derived.subarray(32);
  const part2 = xorInPlace(decryptBlock(data.subarray(23, 39), key), derived.subarray(16, 32));
  // The second block carries the missing eight bytes of the first ciphertext block.
  const encryptedPart1 = Buffer.concat([data.subarray(15, 23), part2.subarray(0, 8)]);
  const part1 = xorInPlace(decryptBlock(encryptedPart1, key), derived.subarray(0, 16));
  const factor = Hash.sha256sha256(Buffer.concat([part1, part2.subarray(8)]));
  return BN.fromBuffer(passfactor).mul(BN.fromBuffer(factor)).umod(Point.getN()).toBuffer({ size: 32 });
}

// Keep the pinned library's Base58Check decoding, WIF handling and validation errors.
export class WalletBip38 extends LegacyBip38 {
  decryptRaw(data: Buffer, passphrase: string, progressCallback: unknown) {
    if (!progressCallback && typeof passphrase === 'string' &&
        typeof process !== 'undefined' && process.versions?.node &&
        typeof crypto.scryptSync === 'function' && typeof crypto.getFips === 'function' && !crypto.getFips() &&
        data.length === 39 && data[0] === 0x01) {
      const type = data[1];
      const flags = data[2];
      const direct = type === 0x42 && (flags === 0xc0 || flags === 0xe0);
      const ecMultiply = type === 0x43 && (flags & 0x24) === flags;
      if (direct || ecMultiply) {
        const password = Buffer.from(passphrase, 'utf8');
        try {
          const privateKey = ecMultiply
            ? decryptECMultiply(data, password, this.scryptParams)
            : this.decryptDirect(data, password);
          return { privateKey, compressed: (flags & 0x20) !== 0 };
        } catch {
          // Providers can disable scrypt, AES-ECB or secp256k1. Let the legacy path report any error.
        } finally {
          password.fill(0);
        }
      }
    }
    return super.decryptRaw(data, passphrase, progressCallback);
  }

  private decryptDirect(data: Buffer, password: Buffer) {
    const derived = crypto.scryptSync(password, data.subarray(3, 7), 64, this.scryptParams);
    return xorInPlace(decryptBlock(data.subarray(7), derived.subarray(32)), derived);
  }
}
