import { ArchiveManifest } from '../archive/types';
import {
  ArchiveIntegrityMismatchError,
  EnvelopeError,
  EnvelopeTruncatedError,
  InvalidArchiveManifestError,
  InvalidMagicBytesError,
  UnsupportedAlgorithmError,
  UnsupportedVersionError,
} from './errors';
import {
  ALGO_AES_256_GCM,
  FORMAT_VERSION_1,
  FORMAT_VERSION_2,
  MAGIC_BYTES,
  MAX_MANIFEST_LENGTH_BYTES,
  MIN_ARCHIVE_ENVELOPE_SIZE_BYTES,
  NONCE_LENGTH_BYTES,
  TAG_LENGTH_BYTES,
} from './format';

export interface PackedArchivePayload {
  /** Ciphertext including 128-bit authentication tag */
  ciphertextWithTag: Uint8Array;
  /** 96-bit nonce */
  iv: Uint8Array;
  /** Archive manifest */
  manifest: ArchiveManifest;
}

export interface UnpackedArchiveEnvelope {
  /** 96-bit nonce */
  iv: Uint8Array;
  /** Validated archive manifest */
  manifest: ArchiveManifest;
  /** Exact raw manifest UTF-8 bytes used as AAD for decryption */
  manifestBytes: Uint8Array;
  /** Ciphertext including 128-bit authentication tag */
  ciphertextWithTag: Uint8Array;
}

/**
 * Inspects a .sbox file header to determine if it is a single-file document (v1)
 * or a multi-file collection archive (v2).
 */
export function detectEnvelopeVersion(fileBytes: Uint8Array): 1 | 2 {
  if (fileBytes.byteLength < 5) {
    throw new EnvelopeTruncatedError('File is too small to read SecureBox header');
  }

  for (let i = 0; i < MAGIC_BYTES.length; i++) {
    if (fileBytes[i] !== MAGIC_BYTES[i]) {
      throw new InvalidMagicBytesError();
    }
  }

  const version = fileBytes[4];
  if (version === FORMAT_VERSION_1) return 1;
  if (version === FORMAT_VERSION_2) return 2;

  throw new UnsupportedVersionError(version);
}

/**
 * Packs a multi-file collection into the .sbox Archive binary envelope (v2).
 */
export function packArchiveEnvelope(payload: PackedArchivePayload): Uint8Array {
  const { ciphertextWithTag, iv, manifest } = payload;

  if (iv.length !== NONCE_LENGTH_BYTES) {
    throw new EnvelopeError(`Invalid IV length: expected ${NONCE_LENGTH_BYTES} bytes, got ${iv.length}`);
  }

  const manifestJson = JSON.stringify(manifest);
  const manifestBytes = new TextEncoder().encode(manifestJson);

  if (manifestBytes.length > MAX_MANIFEST_LENGTH_BYTES) {
    throw new InvalidArchiveManifestError(
      `Archive manifest exceeds maximum allowed size of ${MAX_MANIFEST_LENGTH_BYTES} bytes`
    );
  }

  const headerLength = 4 + 1 + 1 + 1 + NONCE_LENGTH_BYTES + 4 + manifestBytes.length;
  const totalLength = headerLength + ciphertextWithTag.length;

  const buffer = new Uint8Array(totalLength);
  const dataView = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  let offset = 0;

  // 1. Magic Bytes: "SBOX"
  buffer.set(MAGIC_BYTES, offset);
  offset += MAGIC_BYTES.length;

  // 2. Format Version: 0x02
  buffer[offset] = FORMAT_VERSION_2;
  offset += 1;

  // 3. Algorithm ID: 0x01 (AES-256-GCM)
  buffer[offset] = ALGO_AES_256_GCM;
  offset += 1;

  // 4. Nonce Length: 12
  buffer[offset] = NONCE_LENGTH_BYTES;
  offset += 1;

  // 5. Nonce Bytes
  buffer.set(iv, offset);
  offset += NONCE_LENGTH_BYTES;

  // 6. Manifest Length (uint32 Big-Endian)
  dataView.setUint32(offset, manifestBytes.length, false);
  offset += 4;

  // 7. Manifest UTF-8 Bytes
  buffer.set(manifestBytes, offset);
  offset += manifestBytes.length;

  // 8. Ciphertext + Tag
  buffer.set(ciphertextWithTag, offset);

  return buffer;
}

/**
 * Validates and unpacks a .sbox Archive binary envelope (v2).
 */
export function unpackArchiveEnvelope(fileBytes: Uint8Array): UnpackedArchiveEnvelope {
  if (fileBytes.byteLength < MIN_ARCHIVE_ENVELOPE_SIZE_BYTES) {
    throw new EnvelopeTruncatedError(
      `File is too small to be a valid SecureBox archive envelope (minimum ${MIN_ARCHIVE_ENVELOPE_SIZE_BYTES} bytes, got ${fileBytes.byteLength})`
    );
  }

  // 1. Validate Magic Bytes: "SBOX"
  for (let i = 0; i < MAGIC_BYTES.length; i++) {
    if (fileBytes[i] !== MAGIC_BYTES[i]) {
      throw new InvalidMagicBytesError();
    }
  }

  let offset = MAGIC_BYTES.length;

  // 2. Validate Version (Must be 0x02)
  const version = fileBytes[offset];
  if (version !== FORMAT_VERSION_2) {
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

  // 6. Read Manifest Length (uint32 Big-Endian)
  const dataView = new DataView(fileBytes.buffer, fileBytes.byteOffset, fileBytes.byteLength);
  const manifestLength = dataView.getUint32(offset, false);
  offset += 4;

  if (manifestLength > MAX_MANIFEST_LENGTH_BYTES) {
    throw new InvalidArchiveManifestError(
      `Manifest length ${manifestLength} exceeds allowed limit of ${MAX_MANIFEST_LENGTH_BYTES} bytes`
    );
  }

  const minRequiredLength = offset + manifestLength + TAG_LENGTH_BYTES;
  if (fileBytes.byteLength < minRequiredLength) {
    throw new EnvelopeTruncatedError('Encrypted archive payload is incomplete or truncated');
  }

  // 7. Read and validate Manifest JSON
  const manifestBytes = fileBytes.slice(offset, offset + manifestLength);
  offset += manifestLength;

  let manifest: ArchiveManifest;
  try {
    const textDecoder = new TextDecoder('utf-8', { fatal: true });
    const jsonString = textDecoder.decode(manifestBytes);
    manifest = JSON.parse(jsonString) as ArchiveManifest;

    if (!manifest || typeof manifest !== 'object') {
      throw new Error('Manifest must be a JSON object');
    }
    if (manifest.version !== 1) {
      throw new Error(`Unsupported manifest version: ${manifest.version}`);
    }
    if (!Array.isArray(manifest.files)) {
      throw new Error('Manifest files must be an array');
    }
    if (manifest.fileCount !== manifest.files.length) {
      throw new Error(
        `Declared fileCount (${manifest.fileCount}) does not match files array length (${manifest.files.length})`
      );
    }
    if (typeof manifest.totalPlaintextSize !== 'number' || manifest.totalPlaintextSize < 0) {
      throw new Error('Invalid totalPlaintextSize in manifest');
    }

    // Validate each file entry structure
    for (const entry of manifest.files) {
      if (!entry.path || typeof entry.path !== 'string') {
        throw new Error('Invalid path in manifest entry');
      }
      if (typeof entry.size !== 'number' || entry.size < 0) {
        throw new Error(`Invalid size for entry ${entry.path}`);
      }
      if (typeof entry.offset !== 'number' || entry.offset < 0) {
        throw new Error(`Invalid offset for entry ${entry.path}`);
      }
      if (entry.offset + entry.size > manifest.totalPlaintextSize) {
        throw new ArchiveIntegrityMismatchError(
          `Entry ${entry.path} bounds (${entry.offset} + ${entry.size}) exceed total plain text size (${manifest.totalPlaintextSize})`
        );
      }
      if (!entry.sha256 || typeof entry.sha256 !== 'string' || entry.sha256.length !== 64) {
        throw new Error(`Invalid SHA-256 digest for entry ${entry.path}`);
      }
    }
  } catch (error) {
    if (error instanceof EnvelopeError) throw error;
    throw new InvalidArchiveManifestError('Failed to parse or validate archive manifest', error);
  }

  // 8. Remaining bytes: Ciphertext + 128-bit Tag
  const ciphertextWithTag = fileBytes.slice(offset);

  return {
    iv,
    manifest,
    manifestBytes,
    ciphertextWithTag,
  };
}
