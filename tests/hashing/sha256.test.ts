import { describe, expect, it } from 'vitest';
import { canonicalizeHash, compareHashes } from '../../src/core/hashing/compare';
import { computeSha256 } from '../../src/core/hashing/sha256';

describe('SHA-256 Cryptographic Fingerprint Engine', () => {
  it('matches standard NIST test vector for empty string', async () => {
    const empty = new Uint8Array(0);
    const hash = await computeSha256(empty);
    expect(hash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('matches standard NIST test vector for "abc"', async () => {
    const input = new TextEncoder().encode('abc');
    const hash = await computeSha256(input);
    expect(hash).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('matches standard NIST test vector for 448-bit test string', async () => {
    const input = new TextEncoder().encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq');
    const hash = await computeSha256(input);
    expect(hash).toBe('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  });

  it('generates identical fingerprints for identical inputs', async () => {
    const data1 = new TextEncoder().encode('Hello SecureBox');
    const data2 = new TextEncoder().encode('Hello SecureBox');

    const hash1 = await computeSha256(data1);
    const hash2 = await computeSha256(data2);

    expect(hash1).toBe(hash2);
  });

  it('exhibits avalanche effect: a one-byte modification drastically alters the fingerprint', async () => {
    const original = new TextEncoder().encode('Document text with account number: 123456');
    const modified = new TextEncoder().encode('Document text with account number: 123457'); // 1 character difference

    const hashOriginal = await computeSha256(original);
    const hashModified = await computeSha256(modified);

    expect(hashOriginal).not.toBe(hashModified);

    // Calculate differing character count
    let diffCount = 0;
    for (let i = 0; i < hashOriginal.length; i++) {
      if (hashOriginal[i] !== hashModified[i]) diffCount++;
    }

    // Significant avalanche effect across 64 hex characters
    expect(diffCount).toBeGreaterThan(30);
  });

  it('canonicalizes and compares hashes correctly despite formatting differences', () => {
    const expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    const formattedWithUppercaseAndSpaces = '  BA7816BF 8F01CFEA 414140DE 5DAE2223 B00361A3 96177A9C B410FF61 F20015AD  ';

    expect(canonicalizeHash(formattedWithUppercaseAndSpaces)).toBe(expected);

    const result = compareHashes(expected, formattedWithUppercaseAndSpaces);
    expect(result.match).toBe(true);
    expect(result.differingIndices).toHaveLength(0);
  });

  it('identifies mismatch and pinpoints differing indices', () => {
    const hashA = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    // Modify index 0 and index 5
    const hashB = '0a7810bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

    const result = compareHashes(hashA, hashB);
    expect(result.match).toBe(false);
    expect(result.differingIndices).toEqual([0, 5]);
  });
});
