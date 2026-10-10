import { ArchiveManifest } from '../archive/types';
import {
  EnvelopeError,
  EnvelopeTruncatedError,
  InvalidArchiveManifestError,
  InvalidMagicBytesError,
  InvalidManifestIntegerError,
  ManifestEntryBoundsError,
  ManifestFileCountMismatchError,
  ManifestNonContiguousError,
  UnsupportedAlgorithmError,
  UnsupportedVersionError,
} from './errors';
import {
  ALGO_AES_256_GCM,
  FORMAT_VERSION_1,
  FORMAT_VERSION_2,
  MAGIC_BYTES,
  MAX_ARCHIVE_FILE_COUNT,
  MAX_MANIFEST_LENGTH_BYTES,
  MAX_TOTAL_PLAINTEXT_SIZE_BYTES,
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
 * Validates that a value is a safe integer within the specified bounds.
 */
function validateSafeInteger(value: unknown, fieldName: string, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new InvalidManifestIntegerError(`${fieldName} must be a safe integer, got ${JSON.stringify(value)}`);
  }
  if (value < min || value > max) {
    throw new InvalidManifestIntegerError(`${fieldName} must be between ${min} and ${max}, got ${value}`);
  }
  return value;
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

    // SEC-01/SEC-03: Validate integer fields with safe integer checks and bounds
    validateSafeInteger(manifest.fileCount, 'fileCount', 0, MAX_ARCHIVE_FILE_COUNT);
    validateSafeInteger(manifest.totalPlaintextSize, 'totalPlaintextSize', 0, MAX_TOTAL_PLAINTEXT_SIZE_BYTES);

    // Validate fileCount matches actual files array length
    if (manifest.fileCount !== manifest.files.length) {
      throw new ManifestFileCountMismatchError(
        `Declared fileCount (${manifest.fileCount}) does not match files array length (${manifest.files.length})`
      );
    }

    // Validate each file entry structure
    for (const entry of manifest.files) {
      if (!entry.path || typeof entry.path !== 'string') {
        throw new Error('Invalid path in manifest entry');
      }
      validateSafeInteger(entry.size, `size for "${entry.path}"`, 0, MAX_TOTAL_PLAINTEXT_SIZE_BYTES);
      validateSafeInteger(entry.offset, `offset for "${entry.path}"`, 0, MAX_TOTAL_PLAINTEXT_SIZE_BYTES);
      if (!entry.sha256 || typeof entry.sha256 !== 'string' || entry.sha256.length !== 64) {
        throw new Error(`Invalid SHA-256 digest for entry ${entry.path}`);
      }
      if (typeof entry.mimeType !== 'string') {
        throw new Error(`Invalid MIME type for entry ${entry.path}`);
      }

      // Check that entry bounds don't exceed total plaintext size
      const endOffset = entry.offset + entry.size;
      if (!Number.isSafeInteger(endOffset) || endOffset > manifest.totalPlaintextSize) {
        throw new ManifestEntryBoundsError(
          `Entry ${entry.path} bounds (offset ${entry.offset} + size ${entry.size} = ${endOffset}) exceed total plaintext size (${manifest.totalPlaintextSize})`
        );
      }
    }

    // SEC-01/SEC-03: Validate contiguous, non-overlapping ranges starting at offset 0
    if (manifest.files.length > 0) {
      // Sort entries by offset to check contiguity
      const sortedEntries = [...manifest.files].sort((a, b) => a.offset - b.offset);

      // First entry must start at offset 0
      if (sortedEntries[0].offset !== 0) {
        throw new ManifestNonContiguousError(
          `First file entry must start at offset 0, but "${sortedEntries[0].path}" starts at offset ${sortedEntries[0].offset}`
        );
      }

      // Check for overlaps and gaps
      for (let i = 0; i < sortedEntries.length - 1; i++) {
        const current = sortedEntries[i];
        const next = sortedEntries[i + 1];
        const currentEnd = current.offset + current.size;

        if (next.offset < currentEnd) {
          throw new ManifestNonContiguousError(
            `File entries overlap: "${current.path}" (offset ${current.offset}, size ${current.size}, ends at ${currentEnd}) ` +
            `overlaps with "${next.path}" (offset ${next.offset})`
          );
        }

        if (next.offset > currentEnd) {
          throw new ManifestNonContiguousError(
            `Gap detected between file entries: "${current.path}" ends at offset ${currentEnd}, ` +
            `but "${next.path}" starts at offset ${next.offset}`
          );
        }
      }

      // Last entry must end exactly at totalPlaintextSize (no trailing unaccounted bytes)
      const lastEntry = sortedEntries[sortedEntries.length - 1];
      const lastEnd = lastEntry.offset + lastEntry.size;
      if (lastEnd !== manifest.totalPlaintextSize) {
        throw new ManifestNonContiguousError(
          `Final file entry "${lastEntry.path}" ends at offset ${lastEnd}, ` +
          `but totalPlaintextSize is ${manifest.totalPlaintextSize} (${lastEnd !== manifest.totalPlaintextSize ? 'trailing unaccounted bytes' : 'OK'})`
        );
      }
    } else {
      // Empty archive: totalPlaintextSize must be 0
      if (manifest.totalPlaintextSize !== 0) {
        throw new ManifestNonContiguousError(
          `Empty archive must have totalPlaintextSize of 0, got ${manifest.totalPlaintextSize}`
        );
      }
    }

    // SEC-01/SEC-03: Zero-byte files are valid - they have size 0 and occupy no range
    // They must still have valid offsets (which will be equal to the next file's offset or totalPlaintextSize)
    // The contiguity checks above already handle this correctly

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
