import { describe, expect, it } from 'vitest';
import { generateAesKey } from '../../src/core/crypto/aesGcm';
import {
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToHex,
  exportKeyBackup,
  exportKeyToHex,
  hexToBytes,
  importKeyFromBase64,
  importKeyFromHex,
  importKeyFromRaw,
  parseKeyFromInput,
} from '../../src/core/crypto/keyUtils';
import { InvalidKeyError } from '../../src/core/crypto/types';

describe('Key Utilities & Serialization', () => {
  it('exports and imports a 256-bit key via hex string without loss', async () => {
    const key = await generateAesKey();
    const hex = await exportKeyToHex(key);

    expect(hex).toHaveLength(64); // 32 bytes * 2 hex chars
    expect(/^[0-9a-f]{64}$/.test(hex)).toBe(true);

    const importedKey = await importKeyFromHex(hex);
    const reExportedHex = await exportKeyToHex(importedKey);

    expect(reExportedHex).toBe(hex);
  });

  it('correctly converts between bytes and hex', () => {
    const sample = new Uint8Array([0x00, 0x0f, 0x10, 0xff, 0xaa, 0x55]);
    const hex = bytesToHex(sample);
    expect(hex).toBe('000f10ffaa55');

    const roundtrip = hexToBytes(hex);
    expect(roundtrip).toEqual(sample);
  });

  it('correctly converts between bytes and base64url', () => {
    const sample = new Uint8Array([255, 254, 253, 0, 1, 2]);
    const b64 = bytesToBase64Url(sample);
    expect(b64).not.toContain('+');
    expect(b64).not.toContain('/');
    expect(b64).not.toContain('=');

    const roundtrip = base64UrlToBytes(b64);
    expect(roundtrip).toEqual(sample);
  });

  it('imports key directly from base64 string', async () => {
    const key = await generateAesKey();
    const hex = await exportKeyToHex(key);
    const backup = await exportKeyBackup(key);

    const imported = await importKeyFromBase64(backup.keyBase64);
    expect(await exportKeyToHex(imported)).toBe(hex);
  });

  it('exports structured key backup JSON and re-imports successfully', async () => {
    const key = await generateAesKey();
    const backup = await exportKeyBackup(key);

    expect(backup.version).toBe(1);
    expect(backup.algorithm).toBe('AES-256-GCM');
    expect(backup.keyHex).toHaveLength(64);
    expect(backup.keyBase64.length).toBeGreaterThan(40);

    const jsonString = JSON.stringify(backup);
    const importedFromBackup = await parseKeyFromInput(jsonString);
    const reExported = await exportKeyToHex(importedFromBackup);

    expect(reExported).toBe(backup.keyHex);
  });

  it('rejects keys with invalid lengths', async () => {
    // 31 bytes (too short)
    const shortBytes = new Uint8Array(31);
    await expect(importKeyFromRaw(shortBytes)).rejects.toThrow(InvalidKeyError);

    // 33 bytes (too long)
    const longBytes = new Uint8Array(33);
    await expect(importKeyFromRaw(longBytes)).rejects.toThrow(InvalidKeyError);

    // 62 hex chars (31 bytes)
    await expect(importKeyFromHex('aa'.repeat(31))).rejects.toThrow(InvalidKeyError);
  });

  it('rejects non-hex characters in hex import', () => {
    expect(() => hexToBytes('not-a-valid-hex-string-at-all-abcdef0123456789abcdef0123456789zz')).toThrow(
      InvalidKeyError
    );
  });

  it('correctly parses raw hex, base64, and JSON through parseKeyFromInput', async () => {
    const key = await generateAesKey();
    const hex = await exportKeyToHex(key);

    const fromHex = await parseKeyFromInput(hex);
    expect(await exportKeyToHex(fromHex)).toBe(hex);

    const fromHexWithSpaces = await parseKeyFromInput(`  ${hex}  `);
    expect(await exportKeyToHex(fromHexWithSpaces)).toBe(hex);
  });
});
