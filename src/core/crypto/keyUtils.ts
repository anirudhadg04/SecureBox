import { AES_KEY_LENGTH_BITS } from './aesGcm';
import { CryptoError, InvalidKeyError, KeyBackup } from './types';

const EXPECTED_KEY_BYTES = AES_KEY_LENGTH_BITS / 8; // 32 bytes for AES-256

/**
 * Converts a Uint8Array into a lowercase hexadecimal string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Converts a hexadecimal string into a Uint8Array.
 * Throws InvalidKeyError if hex string is invalid.
 */
export function hexToBytes(hex: string): Uint8Array {
  const sanitized = hex.trim().replace(/\s+/g, '');
  if (!/^[0-9a-fA-F]+$/.test(sanitized)) {
    throw new InvalidKeyError('Key contains non-hexadecimal characters');
  }
  if (sanitized.length % 2 !== 0) {
    throw new InvalidKeyError('Hex string length must be an even number');
  }

  const length = sanitized.length / 2;
  const bytes = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    bytes[i] = parseInt(sanitized.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Encodes a Uint8Array to a URL-safe Base64 string (Base64URL).
 */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decodes a Base64 or Base64URL string to a Uint8Array.
 */
export function base64UrlToBytes(str: string): Uint8Array {
  const sanitized = str.trim().replace(/-/g, '+').replace(/_/g, '/');
  // Pad with '=' if necessary
  const padLength = (4 - (sanitized.length % 4)) % 4;
  const padded = sanitized + '='.repeat(padLength);

  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    throw new InvalidKeyError('Invalid Base64 format');
  }
}

/**
 * Exports a CryptoKey to raw 32 bytes.
 */
export async function exportRawKeyBytes(key: CryptoKey): Promise<Uint8Array> {
  try {
    const rawBuffer = await crypto.subtle.exportKey('raw', key);
    return new Uint8Array(rawBuffer);
  } catch (error) {
    throw new CryptoError('Failed to export raw key bytes', error);
  }
}

/**
 * Exports a 256-bit AES CryptoKey as a 64-character hexadecimal string.
 */
export async function exportKeyToHex(key: CryptoKey): Promise<string> {
  const rawBytes = await exportRawKeyBytes(key);
  return bytesToHex(rawBytes);
}

/**
 * Exports a 256-bit AES CryptoKey as a Base64URL string.
 */
export async function exportKeyToBase64Url(key: CryptoKey): Promise<string> {
  const rawBytes = await exportRawKeyBytes(key);
  return bytesToBase64Url(rawBytes);
}

/**
 * Creates a structured JSON backup object of the key for safe offline file export.
 */
export async function exportKeyBackup(key: CryptoKey): Promise<KeyBackup> {
  const rawBytes = await exportRawKeyBytes(key);
  return {
    version: 1,
    algorithm: 'AES-256-GCM',
    keyHex: bytesToHex(rawBytes),
    keyBase64: bytesToBase64Url(rawBytes),
    createdAt: new Date().toISOString(),
  };
}

/**
 * Imports a raw 32-byte (256-bit) buffer into an AES-GCM CryptoKey.
 */
export async function importKeyFromRaw(rawBytes: Uint8Array): Promise<CryptoKey> {
  if (rawBytes.length !== EXPECTED_KEY_BYTES) {
    throw new InvalidKeyError(
      `Invalid key length: expected ${EXPECTED_KEY_BYTES} bytes (256 bits), got ${rawBytes.length} bytes`
    );
  }

  try {
    return await crypto.subtle.importKey(
      'raw',
      rawBytes as BufferSource,
      {
        name: 'AES-GCM',
        length: AES_KEY_LENGTH_BITS,
      },
      true, // extractable
      ['encrypt', 'decrypt']
    );
  } catch (error) {
    throw new InvalidKeyError('Failed to import AES-256 key', error);
  }
}

/**
 * Imports an AES-256 CryptoKey from a 64-character hexadecimal string.
 */
export async function importKeyFromHex(hex: string): Promise<CryptoKey> {
  const rawBytes = hexToBytes(hex);
  return importKeyFromRaw(rawBytes);
}

/**
 * Imports an AES-256 CryptoKey from a Base64 or Base64URL string.
 */
export async function importKeyFromBase64(base64: string): Promise<CryptoKey> {
  const rawBytes = base64UrlToBytes(base64);
  return importKeyFromRaw(rawBytes);
}

/**
 * Parses user input that could be either a 64-character hex string, a Base64 string,
 * or a JSON string from a key backup file.
 */
export async function parseKeyFromInput(input: string): Promise<CryptoKey> {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new InvalidKeyError('Encryption key input cannot be empty');
  }

  // Check if input is a JSON key backup
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const parsed = JSON.parse(trimmed) as Partial<KeyBackup>;
      if (parsed.keyHex && typeof parsed.keyHex === 'string') {
        return await importKeyFromHex(parsed.keyHex);
      }
      if (parsed.keyBase64 && typeof parsed.keyBase64 === 'string') {
        return await importKeyFromBase64(parsed.keyBase64);
      }
    } catch (e) {
      if (e instanceof InvalidKeyError) throw e;
      throw new InvalidKeyError('Invalid key backup JSON structure');
    }
  }

  // Check if exactly 64 hex characters (256-bit key in hex)
  const hexPattern = /^[0-9a-fA-F]{64}$/;
  if (hexPattern.test(trimmed)) {
    return await importKeyFromHex(trimmed);
  }

  // Attempt base64/base64url decode (32 bytes = 43 or 44 base64 chars)
  try {
    const raw = base64UrlToBytes(trimmed);
    if (raw.length === EXPECTED_KEY_BYTES) {
      return await importKeyFromRaw(raw);
    }
  } catch {
    // Fall through to error
  }

  throw new InvalidKeyError(
    'Key format unrecognized. Please provide a 64-character hexadecimal key or a valid SecureBox .key backup file.'
  );
}
