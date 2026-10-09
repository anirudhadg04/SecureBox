import { bytesToHex } from '../crypto/keyUtils';

/**
 * Computes the SHA-256 cryptographic digest of arbitrary binary data
 * using the browser's native Web Crypto API (crypto.subtle.digest).
 *
 * @param data Binary data buffer as Uint8Array.
 * @returns 64-character lowercase hexadecimal string.
 */
export async function computeSha256(data: Uint8Array): Promise<string> {
  const digestBuffer = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return bytesToHex(new Uint8Array(digestBuffer));
}
