/**
 * Core cryptographic types and payload definitions for SecureBox.
 */

export interface SboxMetadata {
  /** Original filename before encryption */
  originalName: string;
  /** MIME type of original document */
  mimeType: string;
  /** Size in bytes of unencrypted plaintext */
  size: number;
  /** Unix timestamp (milliseconds) when encrypted */
  createdAt: number;
  /** Extensible non-secret attributes */
  custom?: Record<string, unknown>;
}

export interface EncryptedPayload {
  /** Ciphertext including appended 128-bit authentication tag */
  ciphertextWithTag: Uint8Array;
  /** 96-bit (12-byte) initialization vector / nonce */
  iv: Uint8Array;
  /** Encrypted file metadata bound via AAD */
  metadata: SboxMetadata;
}

export interface DecryptedPayload {
  /** Restored plaintext byte buffer */
  plaintext: Uint8Array;
  /** Restored and authenticated file metadata */
  metadata: SboxMetadata;
}

export interface KeyBackup {
  version: 1;
  algorithm: 'AES-256-GCM';
  keyHex: string;
  keyBase64: string;
  createdAt: string;
}

export class CryptoError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'CryptoError';
    Object.setPrototypeOf(this, CryptoError.prototype);
  }
}

export class DecryptionError extends CryptoError {
  constructor(message: string = 'Decryption failed: invalid key or corrupted data', cause?: unknown) {
    super(message, cause);
    this.name = 'DecryptionError';
    Object.setPrototypeOf(this, DecryptionError.prototype);
  }
}

export class InvalidKeyError extends CryptoError {
  constructor(message: string = 'Invalid encryption key: key must be exactly 256 bits (32 bytes)', cause?: unknown) {
    super(message, cause);
    this.name = 'InvalidKeyError';
    Object.setPrototypeOf(this, InvalidKeyError.prototype);
  }
}
