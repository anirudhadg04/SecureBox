/**
 * Web Crypto API utilities for recipient-bound document key sharing.
 * Uses standard ECDH with NIST P-256 curve, HKDF-SHA256, and AES-256-GCM.
 */

export interface EcdhKeyPairJwk {
  publicKeyJwk: JsonWebKey;
  privateKeyJwk: JsonWebKey;
}

/**
 * Generates a fresh ECDH keypair on the P-256 curve.
 */
export async function generateSharingKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true, // extractable
    ['deriveKey', 'deriveBits']
  );
}

/**
 * Exports a CryptoKey to JWK format.
 */
export async function exportKeyToJwk(key: CryptoKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey('jwk', key);
}

/**
 * Imports a public JWK into an ECDH CryptoKey.
 */
export async function importPublicJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    []
  );
}

/**
 * Imports a private JWK into an ECDH CryptoKey.
 */
export async function importPrivateJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveKey', 'deriveBits']
  );
}

/**
 * Wraps (encrypts) a 256-bit AES document key specifically for a recipient's ECDH public key.
 *
 * Protocol:
 * 1. Generate an ephemeral ECDH keypair.
 * 2. Perform ECDH key agreement between sender's ephemeral private key and recipient's public key.
 * 3. Derive a 256-bit AES-GCM wrapping key via HKDF (SHA-256) bound to context info.
 * 4. Encrypt the raw 32-byte AES document key using AES-256-GCM.
 * 5. Return the ephemeral public key (JWK) and the wrapped key package (nonce + ciphertext + tag).
 */
export async function wrapKeyForRecipient(
  documentKeyBytes: Uint8Array,
  recipientPublicKeyJwk: JsonWebKey,
  contextInfo: string
): Promise<{
  ephemeralPublicKeyJwk: JsonWebKey;
  wrappedKeyBase64: string;
}> {
  const recipientPublicKey = await importPublicJwk(recipientPublicKeyJwk);
  const ephemeralKeyPair = await generateSharingKeyPair();

  // Derive shared secret
  const sharedBits = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: recipientPublicKey,
    },
    ephemeralKeyPair.privateKey,
    256
  );

  // Import shared secret into HKDF key
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    sharedBits,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  // Derive AES-256-GCM wrapping key
  const wrappingKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32), // zero salt
      info: new TextEncoder().encode(contextInfo),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  // Encrypt the document key
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encryptedKey = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: new TextEncoder().encode(contextInfo),
    },
    wrappingKey,
    documentKeyBytes as BufferSource
  );

  // Package nonce (12B) + encryptedKey
  const combined = new Uint8Array(nonce.length + encryptedKey.byteLength);
  combined.set(nonce, 0);
  combined.set(new Uint8Array(encryptedKey), nonce.length);

  const ephemeralPublicKeyJwk = await exportKeyToJwk(ephemeralKeyPair.publicKey);
  const wrappedKeyBase64 = btoa(String.fromCharCode(...combined));

  return {
    ephemeralPublicKeyJwk,
    wrappedKeyBase64,
  };
}

/**
 * Unwraps (decrypts) a wrapped document key using the recipient's ECDH private key
 * and the sender's ephemeral public key.
 */
export async function unwrapKeyAsRecipient(
  wrappedKeyBase64: string,
  ephemeralPublicKeyJwk: JsonWebKey,
  recipientPrivateKey: CryptoKey,
  contextInfo: string
): Promise<Uint8Array> {
  const ephemeralPublicKey = await importPublicJwk(ephemeralPublicKeyJwk);

  // Perform ECDH key agreement
  const sharedBits = await crypto.subtle.deriveBits(
    {
      name: 'ECDH',
      public: ephemeralPublicKey,
    },
    recipientPrivateKey,
    256
  );

  // Import shared secret into HKDF key
  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    sharedBits,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  // Derive AES-256-GCM wrapping key
  const wrappingKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: new TextEncoder().encode(contextInfo),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // Decode wrapped package
  const binaryString = atob(wrappedKeyBase64);
  const combined = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    combined[i] = binaryString.charCodeAt(i);
  }

  if (combined.length < 12 + 16) {
    throw new Error('Invalid wrapped key payload size.');
  }

  const nonce = combined.slice(0, 12);
  const ciphertextWithTag = combined.slice(12);

  const decryptedRaw = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: new TextEncoder().encode(contextInfo),
    },
    wrappingKey,
    ciphertextWithTag as BufferSource
  );

  return new Uint8Array(decryptedRaw);
}
