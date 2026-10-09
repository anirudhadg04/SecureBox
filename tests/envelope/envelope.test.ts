import { describe, expect, it } from 'vitest';
import { generateAesKey } from '../../src/core/crypto/aesGcm';
import { decryptDocument, encryptDocument } from '../../src/core/crypto/service';
import { DecryptionError } from '../../src/core/crypto/types';
import {
  EnvelopeTruncatedError,
  InvalidMagicBytesError,
  InvalidMetadataError,
  UnsupportedAlgorithmError,
  UnsupportedVersionError,
} from '../../src/core/envelope/errors';
import { packEnvelope } from '../../src/core/envelope/pack';
import { unpackEnvelope } from '../../src/core/envelope/unpack';

describe('SecureBox Binary Envelope (.sbox) & Document Service', () => {
  it('correctly packs and unpacks an encrypted payload', () => {
    const iv = new Uint8Array(12).fill(7);
    const ciphertextWithTag = new Uint8Array(32).fill(42);
    const metadata = {
      originalName: 'tax_return_2025.pdf',
      mimeType: 'application/pdf',
      size: 1024,
      createdAt: 1700000000000,
    };

    const packed = packEnvelope({
      iv,
      ciphertextWithTag,
      metadata,
    });

    // Check magic bytes "SBOX"
    expect(packed[0]).toBe(0x53);
    expect(packed[1]).toBe(0x42);
    expect(packed[2]).toBe(0x4f);
    expect(packed[3]).toBe(0x58);

    const unpacked = unpackEnvelope(packed);
    expect(unpacked.iv).toEqual(iv);
    expect(unpacked.metadata.originalName).toBe('tax_return_2025.pdf');
    expect(unpacked.metadata.mimeType).toBe('application/pdf');
    expect(unpacked.metadata.size).toBe(1024);
    expect(unpacked.ciphertextWithTag).toEqual(ciphertextWithTag);
  });

  it('rejects files smaller than minimum envelope size', () => {
    const tooSmall = new Uint8Array(20);
    expect(() => unpackEnvelope(tooSmall)).toThrow(EnvelopeTruncatedError);
  });

  it('rejects files without valid "SBOX" magic bytes', () => {
    const fake = new Uint8Array(100);
    fake[0] = 0x50; // 'P'
    fake[1] = 0x4b; // 'K' (like a zip file)
    expect(() => unpackEnvelope(fake)).toThrow(InvalidMagicBytesError);
  });

  it('rejects envelopes with unsupported version numbers', () => {
    const iv = new Uint8Array(12);
    const packed = packEnvelope({
      iv,
      ciphertextWithTag: new Uint8Array(16),
      metadata: { originalName: 'a.txt', mimeType: 'text/plain', size: 0, createdAt: 1 },
    });

    // Modify version byte (offset 4) to 2
    packed[4] = 0x02;
    expect(() => unpackEnvelope(packed)).toThrow(UnsupportedVersionError);
  });

  it('rejects envelopes with unsupported algorithm ID', () => {
    const iv = new Uint8Array(12);
    const packed = packEnvelope({
      iv,
      ciphertextWithTag: new Uint8Array(16),
      metadata: { originalName: 'a.txt', mimeType: 'text/plain', size: 0, createdAt: 1 },
    });

    // Modify algorithm byte (offset 5) to 0x99
    packed[5] = 0x99;
    expect(() => unpackEnvelope(packed)).toThrow(UnsupportedAlgorithmError);
  });

  it('rejects envelopes with metadata exceeding maximum limit', () => {
    const hugeMetadataString = 'a'.repeat(5000);
    expect(() =>
      packEnvelope({
        iv: new Uint8Array(12),
        ciphertextWithTag: new Uint8Array(16),
        metadata: {
          originalName: hugeMetadataString,
          mimeType: 'text/plain',
          size: 10,
          createdAt: 1,
        },
      })
    ).toThrow(InvalidMetadataError);
  });

  it('rejects truncated envelopes where payload length is less than declared header', () => {
    const iv = new Uint8Array(12);
    const packed = packEnvelope({
      iv,
      ciphertextWithTag: new Uint8Array(32),
      metadata: { originalName: 'a.txt', mimeType: 'text/plain', size: 0, createdAt: 1 },
    });

    // Truncate the file to slice off tag/ciphertext
    const truncated = packed.subarray(0, packed.length - 20);
    expect(() => unpackEnvelope(truncated)).toThrow(EnvelopeTruncatedError);
  });

  it('executes full encryptDocument -> decryptDocument roundtrip preserving bytes and metadata', async () => {
    const originalContent = new TextEncoder().encode('Confidential contract signed in 2026.');
    const metadata = {
      originalName: 'contract.pdf',
      mimeType: 'application/pdf',
      size: originalContent.length,
    };

    const { sboxBytes, key } = await encryptDocument(originalContent, metadata);

    expect(sboxBytes.length).toBeGreaterThan(originalContent.length);

    const decrypted = await decryptDocument(sboxBytes, key);
    expect(decrypted.plaintext).toEqual(originalContent);
    expect(decrypted.metadata.originalName).toBe('contract.pdf');
    expect(decrypted.metadata.mimeType).toBe('application/pdf');
    expect(decrypted.metadata.size).toBe(originalContent.length);
  });

  it('rejects decryption when an incorrect key is provided to decryptDocument', async () => {
    const originalContent = new TextEncoder().encode('Protected document');
    const { sboxBytes } = await encryptDocument(originalContent, {
      originalName: 'secret.txt',
      mimeType: 'text/plain',
      size: originalContent.length,
    });

    const wrongKey = await generateAesKey();
    await expect(decryptDocument(sboxBytes, wrongKey)).rejects.toThrow(DecryptionError);
  });

  it('fails decryption if metadata inside .sbox is tampered with (AAD binding protection)', async () => {
    const originalContent = new TextEncoder().encode('Medical records data');
    const { sboxBytes, key } = await encryptDocument(originalContent, {
      originalName: 'medical.pdf',
      mimeType: 'application/pdf',
      size: originalContent.length,
    });

    // Find the word "medical" in the envelope and mutate one letter
    const tampered = new Uint8Array(sboxBytes);
    let replaced = false;
    for (let i = 0; i < tampered.length - 7; i++) {
      if (
        tampered[i] === 0x6d && // 'm'
        tampered[i + 1] === 0x65 && // 'e'
        tampered[i + 2] === 0x64 && // 'd'
        tampered[i + 3] === 0x69 && // 'i'
        tampered[i + 4] === 0x63 && // 'c'
        tampered[i + 5] === 0x61 && // 'a'
        tampered[i + 6] === 0x6c // 'l'
      ) {
        tampered[i] = 0x72; // replace 'm' with 'r' -> 'redical'
        replaced = true;
        break;
      }
    }

    expect(replaced).toBe(true);

    // Decryption must be rejected because metadata is authenticated via AAD
    await expect(decryptDocument(tampered, key)).rejects.toThrow(DecryptionError);
  });
});
