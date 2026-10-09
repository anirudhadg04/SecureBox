import { CryptoError, DecryptionError } from './types';

/** Standard nonce length for AES-GCM recommended by NIST SP 800-38D (96 bits = 12 bytes) */
export const AES_GCM_NONCE_LENGTH = 12;

/** Tag length in bits for AES-GCM authentication */
export const AES_GCM_TAG_LENGTH_BITS = 128;

/** Key length in bits for AES-256 */
export const AES_KEY_LENGTH_BITS = 256;

/**
 * Generates a cryptographically secure 256-bit AES-GCM CryptoKey.
 */
export async function generateAesKey(): Promise<CryptoKey> {
  try {
    return await crypto.subtle.generateKey(
      {
        name: 'AES-GCM',
        length: AES_KEY_LENGTH_BITS,
      },
      true, // extractable for safe user backup
      ['encrypt', 'decrypt']
    );
  } catch (error) {
    throw new CryptoError('Failed to generate AES-256 key', error);
  }
}

/**
 * Generates a fresh, cryptographically secure 96-bit (12-byte) initialization vector / nonce.
 * Every encryption operation MUST use a fresh nonce.
 */
export function generateNonce(): Uint8Array {
  const nonce = new Uint8Array(AES_GCM_NONCE_LENGTH);
  crypto.getRandomValues(nonce);
  return nonce;
}

/**
 * Encrypts arbitrary bytes using AES-256-GCM.
 * Web Crypto appends the 128-bit authentication tag to the returned ciphertext.
 *
 * @param key The 256-bit AES-GCM CryptoKey.
 * @param nonce Fresh 96-bit nonce.
 * @param plaintext Bytes to encrypt.
 * @param additionalData Optional additional authenticated data (AAD) to cryptographically bind to the tag.
 * @returns Combined ciphertext and authentication tag as Uint8Array.
 */
export async function encryptBytes(
  key: CryptoKey,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  if (nonce.length !== AES_GCM_NONCE_LENGTH) {
    throw new CryptoError(`Invalid nonce length: expected ${AES_GCM_NONCE_LENGTH} bytes, got ${nonce.length}`);
  }

  try {
    const params: AesGcmParams = {
      name: 'AES-GCM',
      iv: nonce as BufferSource,
      tagLength: AES_GCM_TAG_LENGTH_BITS,
    };

    if (additionalData && additionalData.byteLength > 0) {
      params.additionalData = additionalData as BufferSource;
    }

    const encryptedBuffer = await crypto.subtle.encrypt(params, key, plaintext as BufferSource);
    return new Uint8Array(encryptedBuffer);
  } catch (error) {
    throw new CryptoError('Failed to encrypt data', error);
  }
}

/**
 * Decrypts and authenticates AES-256-GCM ciphertext.
 * Rejects ciphertext if the authentication tag fails or data has been altered.
 *
 * @param key The 256-bit AES-GCM CryptoKey.
 * @param nonce The 96-bit nonce used during encryption.
 * @param ciphertextWithTag Combined ciphertext and 128-bit authentication tag.
 * @param additionalData Optional additional authenticated data (AAD) that was bound during encryption.
 * @returns Restored plaintext as Uint8Array.
 */
export async function decryptBytes(
  key: CryptoKey,
  nonce: Uint8Array,
  ciphertextWithTag: Uint8Array,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  if (nonce.length !== AES_GCM_NONCE_LENGTH) {
    throw new DecryptionError(`Invalid nonce length: expected ${AES_GCM_NONCE_LENGTH} bytes, got ${nonce.length}`);
  }

  try {
    const params: AesGcmParams = {
      name: 'AES-GCM',
      iv: nonce as BufferSource,
      tagLength: AES_GCM_TAG_LENGTH_BITS,
    };

    if (additionalData && additionalData.byteLength > 0) {
      params.additionalData = additionalData as BufferSource;
    }

    const decryptedBuffer = await crypto.subtle.decrypt(params, key, ciphertextWithTag as BufferSource);
    return new Uint8Array(decryptedBuffer);
  } catch (error) {
    // Web Crypto throws DOMException 'OperationError' on authentication failure (wrong key or tampered bytes)
    throw new DecryptionError('Decryption failed: invalid key or corrupted data', error);
  }
}
