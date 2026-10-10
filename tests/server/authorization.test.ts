import { describe, expect, it, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { initSchema } from '../../server/db';
import { generateUuid } from '../../server/crypto';

describe('Server Document Authorization & IDOR Protection', () => {
  let db: Database.Database;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');
    initSchema(db);

    const now = Date.now();
    // Setup two users: Alice (user_a) and Bob (user_b)
    db.prepare(`
      INSERT INTO users (id, username, email, password_hash, password_salt, created_at, updated_at)
      VALUES (?, ?, ?, 'hash', 'salt', ?, ?)
    `).run('user_a', 'alice', 'alice@test.com', now, now);

    db.prepare(`
      INSERT INTO users (id, username, email, password_hash, password_salt, created_at, updated_at)
      VALUES (?, ?, ?, 'hash', 'salt', ?, ?)
    `).run('user_b', 'bob', 'bob@test.com', now, now);

    // Alice owns document doc_a
    db.prepare(`
      INSERT INTO documents (
        id, owner_id, name, ciphertext_size, plaintext_size, mime_type, format_version,
        file_count, storage_path, sha256_ciphertext, wrapped_key_owner, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run('doc_a', 'user_a', 'confidential.sbox', 1024, 800, 'application/pdf', 1, 1, '/data/doc_a.sbox', 'sha', 'key_a', now, now);
  });

  it('prevents IDOR: User B cannot query or delete User A documents directly', () => {
    // User B attempts to access User A's document
    const unauthorizedQuery = db.prepare(`
      SELECT d.id, d.name
      FROM documents d
      WHERE d.id = ? AND (
        d.owner_id = ? OR 
        EXISTS (SELECT 1 FROM document_shares s WHERE s.document_id = d.id AND s.recipient_id = ? AND s.status = 'active')
      )
    `).get('doc_a', 'user_b', 'user_b');

    expect(unauthorizedQuery).toBeUndefined();

    // User B attempts to delete User A's document
    const deleteResult = db.prepare(`
      DELETE FROM documents WHERE id = ? AND owner_id = ?
    `).run('doc_a', 'user_b');

    expect(deleteResult.changes).toBe(0);

    // Document remains intact for Alice
    const docStillExists = db.prepare(`SELECT id FROM documents WHERE id = 'doc_a'`).get();
    expect(docStillExists).toBeDefined();
  });

  it('allows access only when an active share grant exists for the recipient', () => {
    const now = Date.now();
    const shareId = generateUuid();

    // Alice shares doc_a with Bob
    db.prepare(`
      INSERT INTO document_shares (
        id, document_id, sender_id, recipient_id, wrapped_key_recipient,
        ephemeral_public_key_jwk, permission, status, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, 'read', 'active', ?)
    `).run(shareId, 'doc_a', 'user_a', 'user_b', 'wrappedKeyB', '{}', now);

    // Bob now has access through the active share
    const authorizedQuery = db.prepare(`
      SELECT d.id, d.name
      FROM documents d
      WHERE d.id = ? AND (
        d.owner_id = ? OR 
        EXISTS (SELECT 1 FROM document_shares s WHERE s.document_id = d.id AND s.recipient_id = ? AND s.status = 'active')
      )
    `).get('doc_a', 'user_b', 'user_b');

    expect(authorizedQuery).toBeDefined();

    // Revoke share grant
    db.prepare(`UPDATE document_shares SET status = 'revoked', revoked_at = ? WHERE id = ?`).run(now, shareId);

    // Bob no longer has access after revocation
    const revokedQuery = db.prepare(`
      SELECT d.id, d.name
      FROM documents d
      WHERE d.id = ? AND (
        d.owner_id = ? OR 
        EXISTS (SELECT 1 FROM document_shares s WHERE s.document_id = d.id AND s.recipient_id = ? AND s.status = 'active')
      )
    `).get('doc_a', 'user_b', 'user_b');

    expect(revokedQuery).toBeUndefined();
  });
});
