import { decryptArchive } from '../archive/archiveService';
import { ArchiveManifest, RestoredArchiveFile } from '../archive/types';
import { detectEnvelopeVersion } from '../envelope/archiveEnvelope';
import { packEnvelope } from '../envelope/pack';
import { unpackEnvelope } from '../envelope/unpack';
import { decryptBytes, encryptBytes, generateAesKey, generateNonce } from './aesGcm';
import { DecryptedPayload, SboxMetadata } from './types';
import { MetadataSizeMismatchError } from '../envelope/errors';

export interface EncryptFileResult {
  /** Serialized .sbox file bytes containing header, metadata, nonce, and ciphertext+tag */
  sboxBytes: Uint8Array;
  /** The 256-bit CryptoKey used to encrypt this file */
  key: CryptoKey;
  /** Metadata bound to this file */
  metadata: SboxMetadata;
}

export type DecryptAnyResult =
  | {
      type: 'single';
      plaintext: Uint8Array;
      metadata: SboxMetadata;
      downloadBlob: Blob;
      downloadFilename: string;
    }
  | {
      type: 'archive';
      manifest: ArchiveManifest;
      files: RestoredArchiveFile[];
      downloadBlob: Blob;
      downloadFilename: string;
    };

/**
 * High-level service function to securely encrypt a single file buffer.
 * Automatically generates a fresh 256-bit key (if not provided) and fresh 96-bit nonce,
 * cryptographically binds metadata via AAD, and packages the result into a .sbox v1 envelope.
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

  // Pack into the .sbox binary envelope (v1)
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
 * High-level service function to securely unpack and decrypt a single-file .sbox v1 file buffer.
 * Performs format validation, header bounds checking, and authenticated AES-GCM decryption.
 * If authentication fails or any bytes have been tampered with, rejects safely.
 * Validates that the authenticated metadata size matches the actual decrypted plaintext length.
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

  // 3. SEC-05: Validate authenticated metadata size against actual decrypted plaintext length
  if (!Number.isSafeInteger(metadata.size) || metadata.size < 0) {
    throw new MetadataSizeMismatchError(`Invalid size in metadata: ${metadata.size}`);
  }
  if (plaintext.byteLength !== metadata.size) {
    throw new MetadataSizeMismatchError(
      `Decrypted payload size (${plaintext.byteLength} B) does not match authenticated metadata size (${metadata.size} B)`
    );
  }

  return {
    plaintext,
    metadata,
  };
}

/**
 * Universal decryption router that detects the envelope version (v1 single-file or v2 archive)
 * and safely decrypts, authenticates, and unpacks the contents.
 */
export async function decryptAnyDocument(
  sboxBytes: Uint8Array,
  key: CryptoKey
): Promise<DecryptAnyResult> {
  const version = detectEnvelopeVersion(sboxBytes);

  if (version === 1) {
    const { plaintext, metadata } = await decryptDocument(sboxBytes, key);
    const blob = new Blob([plaintext as unknown as BlobPart], {
      type: metadata.mimeType || 'application/octet-stream',
    });
    return {
      type: 'single',
      plaintext,
      metadata,
      downloadBlob: blob,
      downloadFilename: metadata.originalName,
    };
  }

  // Version 2: Multi-file archive
  const restored = await decryptArchive(sboxBytes, key);
  return {
    type: 'archive',
    manifest: restored.manifest,
    files: restored.files,
    downloadBlob: restored.zipBlob,
    downloadFilename: restored.zipFilename,
  };
}
