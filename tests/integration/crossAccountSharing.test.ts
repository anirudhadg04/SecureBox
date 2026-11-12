import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import type { Server } from 'http';
import { createApp } from '../../server';
import { getDatabase } from '../../server/db';
import { hashPassword, generateSecureToken, hashToken } from '../../server/crypto';
import { encryptDocument, decryptDocument } from '../../src/core/crypto/service';
import {
  generateSharingKeyPair,
  exportKeyToJwk,
  wrapKeyForRecipient,
  unwrapKeyAsRecipient,
} from '../../src/core/crypto/sharingKeyUtils';
import { computeSha256 } from '../../src/core/hashing/sha256';

describe('Cross-Account Sharing & Cryptographic Verification End-to-End', () => {
  let server: Server;
  let baseUrl: string;

  beforeEach(() => {
    const app = createApp();
    server = app.listen(0);
    const port = (server.address() as any).port;
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterEach(() => {
    if (server) {
      server.close();
    }
  });

  // Helper to create an authenticated session and published ECDH sharing keypair for a user
  async function createTestAccount(usernamePrefix: string) {
    const db = getDatabase();
    const { hash, salt } = await hashPassword('Password123!');
    const now = Date.now();
    const uniqueSuffix = `${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const userId = `usr_${uniqueSuffix}`;
    const username = `${usernamePrefix}_${uniqueSuffix}`;
    const email = `${username}@example.com`;

    db.prepare(`
      INSERT INTO users (id, username, email, password_hash, password_salt, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(userId, username, email, hash, salt, now, now);

    const sessionToken = generateSecureToken();
    const tokenHash = hashToken(sessionToken);
    const csrfToken = generateSecureToken();
    const sessionId = `ses_${uniqueSuffix}`;

    db.prepare(`
      INSERT INTO sessions (id, user_id, session_token_hash, csrf_token, expires_at, created_at, last_active_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(sessionId, userId, tokenHash, csrfToken, now + 86400000, now, now);

    // Generate real ECDH P-256 sharing keypair
    const keypair = await generateSharingKeyPair();
    const publicJwk = await exportKeyToJwk(keypair.publicKey);
    const privateJwk = await exportKeyToJwk(keypair.privateKey);

    db.prepare(`
      INSERT INTO user_keypairs (user_id, public_key_jwk, encrypted_private_key, key_version, created_at)
      VALUES (?, ?, ?, 1, ?)
    `).run(userId, JSON.stringify(publicJwk), JSON.stringify(privateJwk), now);

    return {
      userId,
      username,
      email,
      csrfToken,
      cookie: `sbox_session=${sessionToken}`,
      keypair,
      publicJwk,
      privateJwk,
    };
  }

  it('Phase 4: Complete cross-account sharing, unwrapping, decryption, isolation, and revocation lifecycle', async () => {
    // 1. Register and authenticate two legitimate accounts: Bob (sender) and Alice (recipient)
    const bob = await createTestAccount('bob');
    const alice = await createTestAccount('alice');
    const eve = await createTestAccount('eve'); // Unrelated third party

    expect(bob.userId).not.toBe(alice.userId);
    expect(bob.username).not.toBe(alice.username);

    // 2. Bob looks up Alice's public key by username to verify recipient identity
    const lookupRes = await fetch(`${baseUrl}/api/sharing/public-key/${alice.username}`, {
      headers: {
        Cookie: bob.cookie,
      },
    });
    expect(lookupRes.status).toBe(200);
    const lookupData = await lookupRes.json();
    expect(lookupData.userId).toBe(alice.userId);
    expect(lookupData.username).toBe(alice.username);
    expect(lookupData.publicKeyJwk.crv).toBe('P-256');

    // 3. Encrypt a synthetic test file as Bob
    const originalContent = 'TOP SECRET RESEARCH DATA - ' + Date.now();
    const originalBytes = new TextEncoder().encode(originalContent);
    const encResult = await encryptDocument(originalBytes, {
      originalName: 'research_notes.txt',
      mimeType: 'text/plain',
      size: originalBytes.length,
    });

    // 4. Bob ingests the encrypted .sbox file into his vault
    const sboxBase64 = Buffer.from(encResult.sboxBytes).toString('base64');
    const sha = await computeSha256(encResult.sboxBytes);
    const rawKeyBuffer = await crypto.subtle.exportKey('raw', encResult.key);
    const rawKeyBytes = new Uint8Array(rawKeyBuffer);
    const rawKeyHex = Buffer.from(rawKeyBytes).toString('hex');

    const uploadRes = await fetch(`${baseUrl}/api/documents`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-SecureBox-CSRF': bob.csrfToken,
        Cookie: bob.cookie,
      },
      body: JSON.stringify({
        name: 'research_notes',
        ciphertextBase64: sboxBase64,
        plaintextSize: originalBytes.length,
        mimeType: 'text/plain',
        formatVersion: 1,
        fileCount: 1,
        sha256Ciphertext: sha,
        wrappedKeyOwner: rawKeyHex,
      }),
    });
    expect(uploadRes.status).toBe(201);
    const uploadData = await uploadRes.json();
    const documentId = uploadData.id;
    expect(documentId).toBeDefined();

    // 5. Wrap document key for Alice using ECDH key agreement bound to docId and Alice's userId
    const contextInfo = `doc:${documentId}:recipient:${alice.userId}:v1`;
    const { ephemeralPublicKeyJwk, wrappedKeyBase64 } = await wrapKeyForRecipient(
      rawKeyBytes,
      lookupData.publicKeyJwk,
      contextInfo
    );

    // 6. Share document key with Alice
    const shareRes = await fetch(`${baseUrl}/api/sharing/share`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-SecureBox-CSRF': bob.csrfToken,
        Cookie: bob.cookie,
      },
      body: JSON.stringify({
        documentId,
        recipientUsername: alice.username,
        wrappedKeyRecipient: wrappedKeyBase64,
        ephemeralPublicKeyJwk,
      }),
    });
    expect(shareRes.status).toBe(201);
    const shareData = await shareRes.json();
    const shareId = shareData.shareId;
    expect(shareId).toBeDefined();

    // 7. Confirm share record is persisted for Alice's backend user ID in SQLite
    const db = getDatabase();
    const shareRow = db.prepare('SELECT * FROM document_shares WHERE id = ?').get(shareId) as any;
    expect(shareRow).toBeDefined();
    expect(shareRow.sender_id).toBe(bob.userId);
    expect(shareRow.recipient_id).toBe(alice.userId);
    expect(shareRow.document_id).toBe(documentId);
    expect(shareRow.status).toBe('active');

    // 8. Confirm Bob sees the share under Shared by me
    const bobSharedByMeRes = await fetch(`${baseUrl}/api/sharing/shared-by-me`, {
      headers: { Cookie: bob.cookie },
    });
    expect(bobSharedByMeRes.status).toBe(200);
    const bobSharedByMeData = await bobSharedByMeRes.json();
    expect(bobSharedByMeData.shares.some((s: any) => s.share_id === shareId && s.recipient_username === alice.username)).toBe(true);

    // 9. Authenticate as Alice in a separate session and confirm it appears under Shared with me
    const aliceSharedWithMeRes = await fetch(`${baseUrl}/api/sharing/shared-with-me`, {
      headers: { Cookie: alice.cookie },
    });
    expect(aliceSharedWithMeRes.status).toBe(200);
    const aliceSharedWithMeData = await aliceSharedWithMeRes.json();
    const aliceShareItem = aliceSharedWithMeData.shares.find((s: any) => s.share_id === shareId);
    expect(aliceShareItem).toBeDefined();
    expect(aliceShareItem.sender_username).toBe(bob.username);
    expect(aliceShareItem.document_name).toBe('research_notes');

    // 10. Alice downloads the encrypted artifact
    const aliceDownloadRes = await fetch(`${baseUrl}/api/documents/${documentId}/download`, {
      headers: { Cookie: alice.cookie },
    });
    expect(aliceDownloadRes.status).toBe(200);
    const downloadedBuffer = Buffer.from(await aliceDownloadRes.arrayBuffer());
    const downloadedSboxBytes = new Uint8Array(downloadedBuffer);
    expect(downloadedSboxBytes.length).toBe(encResult.sboxBytes.length);

    // 11. Alice unwraps the shared key client-side using Alice's private key
    const aliceUnwrapContext = `doc:${aliceShareItem.document_id}:recipient:${alice.userId}:v1`;
    const unwrappedKeyBytes = await unwrapKeyAsRecipient(
      aliceShareItem.wrapped_key_recipient,
      aliceShareItem.ephemeralPublicKeyJwk,
      alice.keypair.privateKey,
      aliceUnwrapContext
    );
    expect(Buffer.from(unwrappedKeyBytes).equals(Buffer.from(rawKeyBytes))).toBe(true);

    // 12. Alice decrypts the downloaded file and verifies contents match original test file
    const unwrappedCryptoKey = await crypto.subtle.importKey(
      'raw',
      unwrappedKeyBytes as unknown as BufferSource,
      { name: 'AES-GCM', length: 256 },
      true,
      ['decrypt']
    );
    const decryptedDoc = await decryptDocument(downloadedSboxBytes, unwrappedCryptoKey);
    const decryptedText = new TextDecoder().decode(decryptedDoc.plaintext);
    expect(decryptedText).toBe(originalContent);
    expect(decryptedDoc.metadata.originalName).toBe('research_notes.txt');

    // 13. Confirm an unrelated third account (Eve) cannot retrieve the share or artifact
    const eveSharedWithMeRes = await fetch(`${baseUrl}/api/sharing/shared-with-me`, {
      headers: { Cookie: eve.cookie },
    });
    const eveSharedWithMeData = await eveSharedWithMeRes.json();
    expect(eveSharedWithMeData.shares.some((s: any) => s.share_id === shareId)).toBe(false);

    const eveDownloadRes = await fetch(`${baseUrl}/api/documents/${documentId}/download`, {
      headers: { Cookie: eve.cookie },
    });
    expect(eveDownloadRes.status).toBe(404); // Access denied / not found

    // 14. Confirm Bob can revoke the share
    const revokeRes = await fetch(`${baseUrl}/api/sharing/revoke`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-SecureBox-CSRF': bob.csrfToken,
        Cookie: bob.cookie,
      },
      body: JSON.stringify({ shareId }),
    });
    expect(revokeRes.status).toBe(200);

    // 15. Confirm revocation prevents subsequent access according to design
    const aliceAfterRevokeRes = await fetch(`${baseUrl}/api/sharing/shared-with-me`, {
      headers: { Cookie: alice.cookie },
    });
    const aliceAfterRevokeData = await aliceAfterRevokeRes.json();
    expect(aliceAfterRevokeData.shares.some((s: any) => s.share_id === shareId)).toBe(false);

    const aliceDownloadAfterRevoke = await fetch(`${baseUrl}/api/documents/${documentId}/download`, {
      headers: { Cookie: alice.cookie },
    });
    expect(aliceDownloadAfterRevoke.status).toBe(404); // Share no longer active -> access denied
  });

  it('rejects sharing if the document ID is not a registered document in the vault', async () => {
    const bob = await createTestAccount('bob_err');
    const alice = await createTestAccount('alice_err');

    const fakeKeypair = await generateSharingKeyPair();
    const fakePublicJwk = await exportKeyToJwk(fakeKeypair.publicKey);

    // Passing filename string instead of valid document UUID
    const shareRes = await fetch(`${baseUrl}/api/sharing/share`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-SecureBox-CSRF': bob.csrfToken,
        Cookie: bob.cookie,
      },
      body: JSON.stringify({
        documentId: 'fake-filename.txt.sbox',
        recipientUsername: alice.username,
        wrappedKeyRecipient: 'AAECAwQFBgcICQoLDA0ODw==',
        ephemeralPublicKeyJwk: fakePublicJwk,
      }),
    });

    expect(shareRes.status).toBe(404);
    const errData = await shareRes.json();
    expect(errData.error).toContain('Document not found');
  });

  it('rejects sharing a document with oneself', async () => {
    const bob = await createTestAccount('bob_self');

    // Create a real document for Bob
    const db = getDatabase();
    const docId = `doc_${Date.now()}`;
    db.prepare(`
      INSERT INTO documents (id, owner_id, name, ciphertext_size, plaintext_size, mime_type, format_version, file_count, storage_path, sha256_ciphertext, wrapped_key_owner, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(docId, bob.userId, 'my_file', 100, 100, 'text/plain', 1, 1, 'dummy_path', 'dummy_hash', 'dummy_key', Date.now(), Date.now());

    const shareRes = await fetch(`${baseUrl}/api/sharing/share`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-SecureBox-CSRF': bob.csrfToken,
        Cookie: bob.cookie,
      },
      body: JSON.stringify({
        documentId: docId,
        recipientUsername: bob.username,
        wrappedKeyRecipient: 'AAECAwQFBgcICQoLDA0ODw==',
        ephemeralPublicKeyJwk: bob.publicJwk,
      }),
    });

    expect(shareRes.status).toBe(400);
    const errData = await shareRes.json();
    expect(errData.error).toContain('Cannot share a document with yourself');
  });
});
