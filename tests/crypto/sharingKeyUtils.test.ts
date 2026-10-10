import { describe, expect, it } from 'vitest';
import {
  generateSharingKeyPair,
  exportKeyToJwk,
  wrapKeyForRecipient,
  unwrapKeyAsRecipient,
} from '../../src/core/crypto/sharingKeyUtils';

describe('Recipient-Bound Asymmetric Key Sharing Engine (ECDH P-256 + HKDF + AES-GCM)', () => {
  it('correctly wraps a 256-bit AES document key and allows only the intended recipient to unwrap it', async () => {
    // 1. Generate document AES-256 key
    const docKeyBytes = crypto.getRandomValues(new Uint8Array(32));

    // 2. Generate Recipient (User B) ECDH KeyPair
    const recipientKeyPair = await generateSharingKeyPair();
    const recipientPublicJwk = await exportKeyToJwk(recipientKeyPair.publicKey);

    // 3. Sender (User A) wraps the key for User B with contextual binding
    const contextInfo = 'doc-uuid-1234:sender-alice:recipient-bob:v1';
    const { ephemeralPublicKeyJwk, wrappedKeyBase64 } = await wrapKeyForRecipient(
      docKeyBytes,
      recipientPublicJwk,
      contextInfo
    );

    expect(wrappedKeyBase64).toBeDefined();
    expect(ephemeralPublicKeyJwk).toBeDefined();

    // 4. Recipient unwraps the key
    const unwrappedBytes = await unwrapKeyAsRecipient(
      wrappedKeyBase64,
      ephemeralPublicKeyJwk,
      recipientKeyPair.privateKey,
      contextInfo
    );

    // 5. Must match bit-for-bit
    expect(unwrappedBytes).toEqual(docKeyBytes);
  });

  it('fails if an unauthorized user tries to unwrap the key with their own private key', async () => {
    const docKeyBytes = crypto.getRandomValues(new Uint8Array(32));
    const intendedRecipientKeyPair = await generateSharingKeyPair();
    const attackerKeyPair = await generateSharingKeyPair();

    const intendedPublicJwk = await exportKeyToJwk(intendedRecipientKeyPair.publicKey);
    const contextInfo = 'doc-uuid-1234:alice:bob';

    const { ephemeralPublicKeyJwk, wrappedKeyBase64 } = await wrapKeyForRecipient(
      docKeyBytes,
      intendedPublicJwk,
      contextInfo
    );

    // Attacker tries to unwrap with attacker's private key
    await expect(
      unwrapKeyAsRecipient(
        wrappedKeyBase64,
        ephemeralPublicKeyJwk,
        attackerKeyPair.privateKey,
        contextInfo
      )
    ).rejects.toThrow();
  });

  it('fails if the context binding (e.g. document ID or recipient) is altered', async () => {
    const docKeyBytes = crypto.getRandomValues(new Uint8Array(32));
    const recipientKeyPair = await generateSharingKeyPair();
    const recipientPublicJwk = await exportKeyToJwk(recipientKeyPair.publicKey);

    const originalContext = 'doc-1234:alice:bob';
    const tamperedContext = 'doc-9999:alice:bob';

    const { ephemeralPublicKeyJwk, wrappedKeyBase64 } = await wrapKeyForRecipient(
      docKeyBytes,
      recipientPublicJwk,
      originalContext
    );

    // Attempt unwrap with mismatched context
    await expect(
      unwrapKeyAsRecipient(
        wrappedKeyBase64,
        ephemeralPublicKeyJwk,
        recipientKeyPair.privateKey,
        tamperedContext
      )
    ).rejects.toThrow();
  });
});
