import { packEnvelope } from '../envelope/pack';
import { unpackEnvelope } from '../envelope/unpack';
import { decryptBytes, encryptBytes, generateAesKey, generateNonce } from './aesGcm';
import { DecryptedPayload, SboxMetadata } from './types';

export interface EncryptFileResult {
  /** Serialized .sbox file bytes containing header, metadata, nonce, and ciphertext+tag */
  sboxBytes: Uint8Array;
  /** The 256-bit CryptoKey used to encrypt this file */
  key: CryptoKey;
  /** Metadata bound to this file */
  metadata: SboxMetadata;
}

/**
 * High-level service function to securely encrypt a file buffer.
 * Automatically generates a fresh 256-bit key (if not provided) and fresh 96-bit nonce,
 * cryptographically binds metadata via AAD, and packages the result into a .sbox envelope.
 *
 * @param fileBytes Raw file bytes to encrypt.
 * @param metadata Non-secret metadata to bind to the file.
 * @param existingKey Optional pre-existing CryptoKey. If omitted, a fresh key is generated.
 */
export async function encryptDocument(
  fileBytes: Uint8Array,
  metadata: Omit<SboxMetadata, 'createdAt'>,
  existingKey?: CryptoKey
): Promise<EncryptFileResult> {
  const key = existingKey ?? (await generateAesKey());
  const nonce = generateNonce();

  const completeMetadata: SboxMetadata = {
    ...metadata,
    createdAt: Date.now(),
  };

  // Convert metadata to UTF-8 bytes for Additional Authenticated Data (AAD)
  const metadataBytes = new TextEncoder().encode(JSON.stringify(completeMetadata));

  // Perform AES-256-GCM authenticated encryption with metadata bound as AAD
  const ciphertextWithTag = await encryptBytes(key, nonce, fileBytes, metadataBytes);

  // Pack into the .sbox binary envelope
  const sboxBytes = packEnvelope({
    ciphertextWithTag,
    iv: nonce,
    metadata: completeMetadata,
  });

  return {
    sboxBytes,
    key,
    metadata: completeMetadata,
  };
}

/**
 * High-level service function to securely unpack and decrypt a .sbox file buffer.
 * Performs format validation, header bounds checking, and authenticated AES-GCM decryption.
 * If authentication fails or any bytes have been tampered with, rejects safely.
 *
 * @param sboxBytes Raw binary content of a .sbox file.
 * @param key The 256-bit CryptoKey.
 * @returns Restored plaintext bytes and validated metadata.
 */
export async function decryptDocument(
  sboxBytes: Uint8Array,
  key: CryptoKey
): Promise<DecryptedPayload> {
  // 1. Unpack envelope and validate structure
  const { iv, metadata, metadataBytes, ciphertextWithTag } = unpackEnvelope(sboxBytes);

  // 2. Authenticated decryption with metadata as AAD
  const plaintext = await decryptBytes(key, iv, ciphertextWithTag, metadataBytes);

  return {
    plaintext,
    metadata,
  };
}
