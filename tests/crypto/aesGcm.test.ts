import { describe, expect, it } from 'vitest';
import {
  decryptBytes,
  encryptBytes,
  generateAesKey,
  generateNonce,
} from '../../src/core/crypto/aesGcm';
import { DecryptionError } from '../../src/core/crypto/types';

describe('AES-256-GCM Core Crypto Engine', () => {
  it('encrypts and decrypts to exactly the original bytes (roundtrip)', async () => {
    const key = await generateAesKey();
    const nonce = generateNonce();
    const originalText = 'Sensitive Document Content: 1234567890';
    const plaintext = new TextEncoder().encode(originalText);

    const ciphertextWithTag = await encryptBytes(key, nonce, plaintext);
    const restoredBytes = await decryptBytes(key, nonce, ciphertextWithTag);

    expect(new TextDecoder().decode(restoredBytes)).toBe(originalText);
    expect(restoredBytes).toEqual(plaintext);
  });

  it('correctly handles empty (0-byte) files', async () => {
    const key = await generateAesKey();
    const nonce = generateNonce();
    const emptyPlaintext = new Uint8Array(0);

    const ciphertextWithTag = await encryptBytes(key, nonce, emptyPlaintext);
    // 0-byte plaintext with 128-bit tag produces a 16-byte payload
    expect(ciphertextWithTag.length).toBe(16);

    const restoredBytes = await decryptBytes(key, nonce, ciphertextWithTag);
    expect(restoredBytes.length).toBe(0);
  });

  it('correctly encrypts and decrypts larger binary data', async () => {
    const key = await generateAesKey();
    const nonce = generateNonce();
    const binaryData = new Uint8Array(65536); // 64 KiB
    for (let i = 0; i < binaryData.length; i++) {
      binaryData[i] = i % 256;
    }

    const ciphertextWithTag = await encryptBytes(key, nonce, binaryData);
    const restoredBytes = await decryptBytes(key, nonce, ciphertextWithTag);

    expect(restoredBytes.length).toBe(binaryData.length);
    expect(restoredBytes).toEqual(binaryData);
  });

  it('rejects decryption when a wrong key is used', async () => {
    const correctKey = await generateAesKey();
    const wrongKey = await generateAesKey();
    const nonce = generateNonce();
    const plaintext = new TextEncoder().encode('Confidential Information');

    const ciphertextWithTag = await encryptBytes(correctKey, nonce, plaintext);

    await expect(decryptBytes(wrongKey, nonce, ciphertextWithTag)).rejects.toThrow(DecryptionError);
  });

  it('rejects decryption when any byte of the ciphertext is modified', async () => {
    const key = await generateAesKey();
    const nonce = generateNonce();
    const plaintext = new TextEncoder().encode('Authenticity is critical');

    const ciphertextWithTag = await encryptBytes(key, nonce, plaintext);

    // Tamper with one byte in the ciphertext portion
    const tampered = new Uint8Array(ciphertextWithTag);
    tampered[0] ^= 0xff; // flip bits

    await expect(decryptBytes(key, nonce, tampered)).rejects.toThrow(DecryptionError);
  });

  it('rejects decryption when the authentication tag is tampered with', async () => {
    const key = await generateAesKey();
    const nonce = generateNonce();
    const plaintext = new TextEncoder().encode('Integrity verified');

    const ciphertextWithTag = await encryptBytes(key, nonce, plaintext);

    // Tamper with the last byte (part of the 16-byte authentication tag)
    const tampered = new Uint8Array(ciphertextWithTag);
    tampered[tampered.length - 1] ^= 0x01;

    await expect(decryptBytes(key, nonce, tampered)).rejects.toThrow(DecryptionError);
  });

  it('rejects decryption when additional authenticated data (AAD) is modified', async () => {
    const key = await generateAesKey();
    const nonce = generateNonce();
    const plaintext = new TextEncoder().encode('Protected document');
    const correctAad = new TextEncoder().encode('filename=passport.pdf');
    const tamperedAad = new TextEncoder().encode('filename=fake.pdf');

    const ciphertextWithTag = await encryptBytes(key, nonce, plaintext, correctAad);

    // Should succeed with matching AAD
    const restored = await decryptBytes(key, nonce, ciphertextWithTag, correctAad);
    expect(new TextDecoder().decode(restored)).toBe('Protected document');

    // Must fail if AAD does not match
    await expect(decryptBytes(key, nonce, ciphertextWithTag, tamperedAad)).rejects.toThrow(DecryptionError);
    await expect(decryptBytes(key, nonce, ciphertextWithTag, undefined)).rejects.toThrow(DecryptionError);
  });

  it('rejects decryption if the nonce is altered', async () => {
    const key = await generateAesKey();
    const nonce = generateNonce();
    const plaintext = new TextEncoder().encode('Nonce binding');

    const ciphertextWithTag = await encryptBytes(key, nonce, plaintext);

    const alteredNonce = new Uint8Array(nonce);
    alteredNonce[0] ^= 0x01;

    await expect(decryptBytes(key, alteredNonce, ciphertextWithTag)).rejects.toThrow(DecryptionError);
  });
});
