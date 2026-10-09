import { SboxMetadata } from '../crypto/types';
import {
  EnvelopeError,
  EnvelopeTruncatedError,
  InvalidMagicBytesError,
  InvalidMetadataError,
  UnsupportedAlgorithmError,
  UnsupportedVersionError,
} from './errors';
import {
  ALGO_AES_256_GCM,
  FORMAT_VERSION_1,
  MAGIC_BYTES,
  MAX_METADATA_LENGTH_BYTES,
  MIN_ENVELOPE_SIZE_BYTES,
  NONCE_LENGTH_BYTES,
  TAG_LENGTH_BYTES,
} from './format';

export interface UnpackedEnvelope {
  /** 96-bit initialization vector */
  iv: Uint8Array;
  /** Deserialized and validated file metadata */
  metadata: SboxMetadata;
  /** Exact raw metadata bytes (used as AAD for authenticated decryption) */
  metadataBytes: Uint8Array;
  /** Ciphertext including appended 128-bit authentication tag */
  ciphertextWithTag: Uint8Array;
}

/**
 * Validates and unpacks a .sbox binary envelope.
 * Strictly verifies header structure, magic bytes, versions, and boundaries
 * before exposing cryptographic fields.
 *
 * @param fileBytes Binary buffer representing the complete .sbox file.
 * @returns Unpacked components ready for authenticated decryption.
 */
export function unpackEnvelope(fileBytes: Uint8Array): UnpackedEnvelope {
  if (fileBytes.byteLength < MIN_ENVELOPE_SIZE_BYTES) {
    throw new EnvelopeTruncatedError(
      `File is too small to be a valid SecureBox envelope (minimum ${MIN_ENVELOPE_SIZE_BYTES} bytes, got ${fileBytes.byteLength})`
    );
  }

  // 1. Validate Magic Bytes: "SBOX"
  for (let i = 0; i < MAGIC_BYTES.length; i++) {
    if (fileBytes[i] !== MAGIC_BYTES[i]) {
      throw new InvalidMagicBytesError();
    }
  }

  let offset = MAGIC_BYTES.length;

  // 2. Validate Version
  const version = fileBytes[offset];
  if (version !== FORMAT_VERSION_1) {
    throw new UnsupportedVersionError(version);
  }
  offset += 1;

  // 3. Validate Algorithm ID
  const algoId = fileBytes[offset];
  if (algoId !== ALGO_AES_256_GCM) {
    throw new UnsupportedAlgorithmError(algoId);
  }
  offset += 1;

  // 4. Validate Nonce Length
  const nonceLength = fileBytes[offset];
  if (nonceLength !== NONCE_LENGTH_BYTES) {
    throw new EnvelopeError(`Invalid nonce length in header: expected ${NONCE_LENGTH_BYTES}, got ${nonceLength}`);
  }
  offset += 1;

  // 5. Read Nonce
  const iv = fileBytes.slice(offset, offset + NONCE_LENGTH_BYTES);
  offset += NONCE_LENGTH_BYTES;

  // 6. Read Metadata Length
  const dataView = new DataView(fileBytes.buffer, fileBytes.byteOffset, fileBytes.byteLength);
  const metadataLength = dataView.getUint16(offset, false);
  offset += 2;

  if (metadataLength > MAX_METADATA_LENGTH_BYTES) {
    throw new InvalidMetadataError(
      `Metadata length ${metadataLength} exceeds allowed limit of ${MAX_METADATA_LENGTH_BYTES} bytes`
    );
  }

  const minRequiredLength = offset + metadataLength + TAG_LENGTH_BYTES;
  if (fileBytes.byteLength < minRequiredLength) {
    throw new EnvelopeTruncatedError('Encrypted file payload is incomplete or truncated');
  }

  // 7. Read and parse Metadata bytes
  const metadataBytes = fileBytes.slice(offset, offset + metadataLength);
  offset += metadataLength;

  let metadata: SboxMetadata;
  try {
    const textDecoder = new TextDecoder('utf-8', { fatal: true });
    const jsonString = textDecoder.decode(metadataBytes);
    metadata = JSON.parse(jsonString) as SboxMetadata;

    if (!metadata || typeof metadata !== 'object') {
      throw new Error('Metadata must be a JSON object');
    }
    if (typeof metadata.originalName !== 'string') {
      throw new Error('Missing or invalid originalName in metadata');
    }
    if (typeof metadata.size !== 'number' || metadata.size < 0) {
      throw new Error('Missing or invalid size in metadata');
    }
  } catch (error) {
    throw new InvalidMetadataError('Failed to parse envelope metadata header', error);
  }

  // 8. Remaining bytes: Ciphertext + Tag
  const ciphertextWithTag = fileBytes.slice(offset);

  return {
    iv,
    metadata,
    metadataBytes,
    ciphertextWithTag,
  };
}
