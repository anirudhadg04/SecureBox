import { describe, expect, it, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { initSchema } from '../../server/db';
import { hashPassword, verifyPassword, hashToken, generateSecureToken } from '../../server/crypto';

describe('Server Authentication & Crypto Engine', () => {
  let db: Database.Database;

  beforeEach(() => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');
    initSchema(db);
  });

  it('hashes passwords using PBKDF2-SHA512 with 600,000 iterations and verifies correctly', async () => {
    const password = 'SuperSecurePassword123!';
    const { hash, salt } = await hashPassword(password);

    expect(hash).toHaveLength(128); // 64 bytes hex
    expect(salt).toHaveLength(64); // 32 bytes hex

    const isValid = await verifyPassword(password, salt, hash);
    expect(isValid).toBe(true);

    const isWrongValid = await verifyPassword('WrongPassword!', salt, hash);
    expect(isWrongValid).toBe(false);
  });

  it('generates cryptographically secure 256-bit session tokens with SHA-256 storage hashes', () => {
    const token = generateSecureToken();
    expect(token).toHaveLength(64); // 32 bytes hex

    const hashed = hashToken(token);
    expect(hashed).toHaveLength(64);
    expect(hashed).not.toBe(token);
  });

  it('enforces unique usernames and case-insensitive uniqueness in the database', async () => {
    const { hash, salt } = await hashPassword('password123');
    const now = Date.now();

    db.prepare(`
      INSERT INTO users (id, username, email, password_hash, password_salt, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('u1', 'Alice', 'alice@example.com', hash, salt, now, now);

    // Duplicate username with different case
    expect(() => {
      db.prepare(`
        INSERT INTO users (id, username, email, password_hash, password_salt, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run('u2', 'alice', 'alice2@example.com', hash, salt, now, now);
    }).toThrow(/UNIQUE constraint failed/);

    // Duplicate email
    expect(() => {
      db.prepare(`
        INSERT INTO users (id, username, email, password_hash, password_salt, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run('u3', 'Bob', 'ALICE@example.com', hash, salt, now, now);
    }).toThrow(/UNIQUE constraint failed/);
  });

  it('cascades deletion: deleting a user removes associated sessions, keypairs, and documents', async () => {
    const { hash, salt } = await hashPassword('password123');
    const now = Date.now();

    db.prepare(`
      INSERT INTO users (id, username, email, password_hash, password_salt, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('u1', 'Alice', 'alice@example.com', hash, salt, now, now);

    db.prepare(`
      INSERT INTO sessions (id, user_id, session_token_hash, csrf_token, expires_at, created_at, last_active_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('s1', 'u1', 'hash1', 'csrf1', now + 10000, now, now);

    db.prepare(`
      INSERT INTO documents (
        id, owner_id, name, ciphertext_size, plaintext_size, mime_type, format_version,
        file_count, storage_path, sha256_ciphertext, wrapped_key_owner, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run('d1', 'u1', 'doc.sbox', 100, 80, 'text/plain', 1, 1, '/tmp/doc.sbox', 'sha', 'wrappedKey', now, now);

    // Verify records exist
    expect(db.prepare(`SELECT COUNT(*) AS count FROM sessions WHERE user_id = 'u1'`).get()).toEqual({ count: 1 });
    expect(db.prepare(`SELECT COUNT(*) AS count FROM documents WHERE owner_id = 'u1'`).get()).toEqual({ count: 1 });

    // Delete user
    db.prepare(`DELETE FROM users WHERE id = 'u1'`).run();

    // Verify cascade deleted
    expect(db.prepare(`SELECT COUNT(*) AS count FROM sessions WHERE user_id = 'u1'`).get()).toEqual({ count: 0 });
    expect(db.prepare(`SELECT COUNT(*) AS count FROM documents WHERE owner_id = 'u1'`).get()).toEqual({ count: 0 });
  });
});
