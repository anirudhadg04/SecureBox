import { EncryptedPayload } from '../crypto/types';
import { EnvelopeError, InvalidMetadataError } from './errors';
import {
  ALGO_AES_256_GCM,
  FORMAT_VERSION_1,
  MAGIC_BYTES,
  MAX_METADATA_LENGTH_BYTES,
  NONCE_LENGTH_BYTES,
} from './format';

/**
 * Serializes an EncryptedPayload into the .sbox binary container.
 *
 * @param payload Encrypted ciphertext, nonce, and associated metadata.
 * @returns Self-contained binary Uint8Array ready for disk storage or download.
 */
export function packEnvelope(payload: EncryptedPayload): Uint8Array {
  const { ciphertextWithTag, iv, metadata } = payload;

  if (iv.length !== NONCE_LENGTH_BYTES) {
    throw new EnvelopeError(`Invalid IV length: expected ${NONCE_LENGTH_BYTES} bytes, got ${iv.length}`);
  }

  // Serialize metadata to UTF-8
  const textEncoder = new TextEncoder();
  const metadataString = JSON.stringify(metadata);
  const metadataBytes = textEncoder.encode(metadataString);

  if (metadataBytes.length > MAX_METADATA_LENGTH_BYTES) {
    throw new InvalidMetadataError(
      `Metadata exceeds maximum allowed size of ${MAX_METADATA_LENGTH_BYTES} bytes (actual: ${metadataBytes.length} bytes)`
    );
  }

  const headerLength = 4 + 1 + 1 + 1 + NONCE_LENGTH_BYTES + 2 + metadataBytes.length;
  const totalLength = headerLength + ciphertextWithTag.length;

  const buffer = new Uint8Array(totalLength);
  const dataView = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

  let offset = 0;

  // 1. Magic Bytes: "SBOX"
  buffer.set(MAGIC_BYTES, offset);
  offset += MAGIC_BYTES.length;

  // 2. Format Version: 0x01
  buffer[offset] = FORMAT_VERSION_1;
  offset += 1;

  // 3. Algorithm ID: 0x01
  buffer[offset] = ALGO_AES_256_GCM;
  offset += 1;

  // 4. Nonce Length: 12
  buffer[offset] = NONCE_LENGTH_BYTES;
  offset += 1;

  // 5. Nonce Bytes
  buffer.set(iv, offset);
  offset += NONCE_LENGTH_BYTES;

  // 6. Metadata Length (uint16 Big-Endian)
  dataView.setUint16(offset, metadataBytes.length, false);
  offset += 2;

  // 7. Metadata UTF-8 Bytes
  buffer.set(metadataBytes, offset);
  offset += metadataBytes.length;

  // 8. Ciphertext + Tag
  buffer.set(ciphertextWithTag, offset);

  return buffer;
}
