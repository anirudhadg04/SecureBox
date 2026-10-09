import { describe, expect, it } from 'vitest';
import { decryptDocument, encryptDocument } from '../../src/core/crypto/service';
import { computeSha256 } from '../../src/core/hashing/sha256';
import { compareHashes } from '../../src/core/hashing/compare';
import { DecryptionError } from '../../src/core/crypto/types';

describe('SecureBox End-to-End Workflow Integration', () => {
  it('completes the full protect -> verify -> decrypt -> verify lifecycle', async () => {
    // 1. Original sensitive document simulation
    const originalText = `CONFIDENTIAL CLIENT DOSSIER
Identifier: 9482-AD-2026
Notes: All privileges reserved. Bitwise fidelity required.`;
    const originalBytes = new TextEncoder().encode(originalText);

    // 2. Compute original fingerprint
    const originalFingerprint = await computeSha256(originalBytes);
    expect(originalFingerprint).toHaveLength(64);

    // 3. Encrypt document to .sbox container
    const { sboxBytes, key, metadata } = await encryptDocument(originalBytes, {
      originalName: 'dossier.txt',
      mimeType: 'text/plain',
      size: originalBytes.length,
    });

    expect(metadata.originalName).toBe('dossier.txt');
    expect(sboxBytes.length).toBeGreaterThan(originalBytes.length);

    // 4. Verify that .sbox ciphertext has a completely different hash from plaintext
    const sboxFingerprint = await computeSha256(sboxBytes);
    expect(sboxFingerprint).not.toBe(originalFingerprint);

    // 5. Decrypt document using key
    const decrypted = await decryptDocument(sboxBytes, key);
    expect(decrypted.metadata.originalName).toBe('dossier.txt');
    expect(decrypted.metadata.size).toBe(originalBytes.length);

    // 6. Compute restored document fingerprint
    const restoredFingerprint = await computeSha256(decrypted.plaintext);

    // 7. Verify bitwise equality between original and restored
    const comparison = compareHashes(restoredFingerprint, originalFingerprint);
    expect(comparison.match).toBe(true);
    expect(new TextDecoder().decode(decrypted.plaintext)).toBe(originalText);
  });

  it('detects tampering during transit and rejects decryption', async () => {
    const originalBytes = new TextEncoder().encode('Integrity critical message.');
    const { sboxBytes, key } = await encryptDocument(originalBytes, {
      originalName: 'message.txt',
      mimeType: 'text/plain',
      size: originalBytes.length,
    });

    // Compute legitimate .sbox hash
    const legitimateSboxHash = await computeSha256(sboxBytes);

    // Simulate an attacker corrupting or altering a single byte in ciphertext
    const tamperedSbox = new Uint8Array(sboxBytes);
    tamperedSbox[tamperedSbox.length - 5] ^= 0x55;

    // Tampered file has a divergent hash
    const tamperedSboxHash = await computeSha256(tamperedSbox);
    const hashCheck = compareHashes(tamperedSboxHash, legitimateSboxHash);
    expect(hashCheck.match).toBe(false);

    // Decryption of tampered container MUST fail
    await expect(decryptDocument(tamperedSbox, key)).rejects.toThrow(DecryptionError);
  });
});
