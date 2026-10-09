/**
 * Specification and constants for the SecureBox (.sbox) binary envelope format.
 *
 * Binary Layout (v1):
 * +-----------------------------------------------------------------------+
 * | Offset | Length (bytes) | Field Description                           |
 * +-----------------------------------------------------------------------+
 * | 0      | 4              | Magic Bytes: ASCII "SBOX" (0x53, 42, 4F, 58)|
 * | 4      | 1              | Version: 0x01                               |
 * | 5      | 1              | Algorithm ID: 0x01 (AES-256-GCM)            |
 * | 6      | 1              | Nonce/IV Length: 0x0C (12 bytes)            |
 * | 7      | 12             | Nonce/IV Bytes                              |
 * | 19     | 2              | Metadata Length: uint16 Big-Endian          |
 * | 21     | M              | Metadata (UTF-8 JSON)                       |
 * | 21 + M | Rest           | Ciphertext + 128-bit Authentication Tag     |
 * +-----------------------------------------------------------------------+
 */

/** ASCII Magic Bytes "SBOX" */
export const MAGIC_BYTES = new Uint8Array([0x53, 0x42, 0x4f, 0x58]);

/** Current binary format version for single files */
export const FORMAT_VERSION_1 = 0x01;

/** Binary format version for multi-file archives */
export const FORMAT_VERSION_2 = 0x02;

/** Algorithm ID for AES-256-GCM */
export const ALGO_AES_256_GCM = 0x01;

/** Standard nonce length in bytes */
export const NONCE_LENGTH_BYTES = 12;

/** Tag length in bytes */
export const TAG_LENGTH_BYTES = 16;

/** Maximum allowable single-file metadata length in bytes (4 KiB safety limit) */
export const MAX_METADATA_LENGTH_BYTES = 4096;

/** Maximum allowable archive manifest length in bytes (1 MiB safety limit) */
export const MAX_MANIFEST_LENGTH_BYTES = 1024 * 1024;

/** Minimum size of a valid .sbox single-file envelope: Header (21B) + Min Tag (16B) = 37 bytes */
export const MIN_ENVELOPE_SIZE_BYTES = 4 + 1 + 1 + 1 + NONCE_LENGTH_BYTES + 2 + TAG_LENGTH_BYTES;

/** Minimum size of a valid .sbox archive envelope: Header (23B) + Min Tag (16B) = 39 bytes */
export const MIN_ARCHIVE_ENVELOPE_SIZE_BYTES = 4 + 1 + 1 + 1 + NONCE_LENGTH_BYTES + 4 + TAG_LENGTH_BYTES;

