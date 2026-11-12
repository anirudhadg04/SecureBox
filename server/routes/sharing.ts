import { Router, Response } from 'express';
import { getDatabase } from '../db';
import { generateUuid } from '../crypto';
import { AuthenticatedRequest, requireAuth, requireCsrf } from '../middleware';

export const sharingRouter = Router();

/**
 * GET /api/sharing/public-key/:username
 * Looks up a recipient's published ECDH public key (JWK) by username.
 */
sharingRouter.get('/public-key/:username', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  const usernameParam = req.params.username;
  const targetUsername = (typeof usernameParam === 'string' ? usernameParam : '').trim().toLowerCase();
  const db = getDatabase();

  const user = db.prepare(`
    SELECT u.id, u.username, k.public_key_jwk, k.key_version
    FROM users u
    JOIN user_keypairs k ON u.id = k.user_id
    WHERE lower(u.username) = ?
  `).get(targetUsername) as {
    id: string;
    username: string;
    public_key_jwk: string;
    key_version: number;
  } | undefined;

  if (!user) {
    res.status(404).json({ error: 'User does not exist or has not initialized a sharing keypair.' });
    return;
  }

  res.json({
    userId: user.id,
    username: user.username,
    publicKeyJwk: JSON.parse(user.public_key_jwk),
    keyVersion: user.key_version,
  });
});

/**
 * POST /api/sharing/keypair
 * Registers or updates the authenticated user's sharing keypair.
 * Stores public key in plaintext and user-encrypted private key.
 */
sharingRouter.post('/keypair', requireAuth, requireCsrf, (req: AuthenticatedRequest, res: Response): void => {
  const userId = req.user!.id;
  const { publicKeyJwk, encryptedPrivateKey, keyVersion = 1 } = req.body;

  if (!publicKeyJwk || !encryptedPrivateKey) {
    res.status(400).json({ error: 'Public key JWK and encrypted private key are required.' });
    return;
  }

  const db = getDatabase();
  const now = Date.now();

  db.prepare(`
    INSERT INTO user_keypairs (user_id, public_key_jwk, encrypted_private_key, key_version, created_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      public_key_jwk = excluded.public_key_jwk,
      encrypted_private_key = excluded.encrypted_private_key,
      key_version = excluded.key_version
  `).run(
    userId,
    JSON.stringify(publicKeyJwk),
    encryptedPrivateKey,
    keyVersion,
    now
  );

  res.json({ message: 'Sharing keypair registered successfully.' });
});

/**
 * GET /api/sharing/keypair
 * Retrieves the authenticated user's own keypair (including encrypted private key).
 */
sharingRouter.get('/keypair', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  const userId = req.user!.id;
  const db = getDatabase();

  const keypair = db.prepare(`
    SELECT public_key_jwk, encrypted_private_key, key_version
    FROM user_keypairs
    WHERE user_id = ?
  `).get(userId) as {
    public_key_jwk: string;
    encrypted_private_key: string;
    key_version: number;
  } | undefined;

  if (!keypair) {
    res.status(404).json({ error: 'Keypair not found.' });
    return;
  }

  res.json({
    publicKeyJwk: JSON.parse(keypair.public_key_jwk),
    encryptedPrivateKey: keypair.encrypted_private_key,
    keyVersion: keypair.key_version,
  });
});

/**
 * POST /api/sharing/share
 * Creates a recipient-bound document share grant.
 */
sharingRouter.post('/share', requireAuth, requireCsrf, (req: AuthenticatedRequest, res: Response): void => {
  const senderId = req.user!.id;
  const {
    documentId,
    recipientUsername,
    wrappedKeyRecipient,
    ephemeralPublicKeyJwk,
  } = req.body;

  if (!documentId || !recipientUsername || !wrappedKeyRecipient || !ephemeralPublicKeyJwk) {
    res.status(400).json({ error: 'Missing required sharing parameters.' });
    return;
  }

  const db = getDatabase();

  // Verify sender is owner of the document
  const doc = db.prepare(`SELECT id, name FROM documents WHERE id = ? AND owner_id = ?`).get(documentId, senderId);
  if (!doc) {
    res.status(404).json({ error: 'Document not found or you are not the owner.' });
    return;
  }

  // Look up recipient
  const recipient = db.prepare(`SELECT id, username FROM users WHERE lower(username) = ?`).get(
    recipientUsername.trim().toLowerCase()
  ) as { id: string; username: string } | undefined;

  if (!recipient) {
    res.status(404).json({ error: 'Recipient username not found.' });
    return;
  }

  if (recipient.id === senderId) {
    res.status(400).json({ error: 'Cannot share a document with yourself.' });
    return;
  }

  const shareId = generateUuid();
  const now = Date.now();

  // Revoke any previous active share for this document and recipient
  db.prepare(`
    UPDATE document_shares SET status = 'revoked', revoked_at = ?
    WHERE document_id = ? AND recipient_id = ? AND status = 'active'
  `).run(now, documentId, recipient.id);

  // Insert share
  db.prepare(`
    INSERT INTO document_shares (
      id, document_id, sender_id, recipient_id, wrapped_key_recipient,
      ephemeral_public_key_jwk, permission, status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, 'read', 'active', ?)
  `).run(
    shareId,
    documentId,
    senderId,
    recipient.id,
    wrappedKeyRecipient,
    JSON.stringify(ephemeralPublicKeyJwk),
    now
  );

  res.status(201).json({
    shareId,
    recipientUsername: recipient.username,
    createdAt: now,
  });
});

/**
 * GET /api/sharing/shared-with-me
 * Lists documents shared with the authenticated user.
 */
sharingRouter.get('/shared-with-me', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  const userId = req.user!.id;
  const db = getDatabase();

  const shares = db.prepare(`
    SELECT 
      s.id AS share_id, s.document_id, s.wrapped_key_recipient, s.ephemeral_public_key_jwk,
      s.created_at AS shared_at,
      u.username AS sender_username,
      d.name AS document_name, d.ciphertext_size, d.plaintext_size, d.mime_type, d.format_version, d.file_count
    FROM document_shares s
    JOIN documents d ON s.document_id = d.id
    JOIN users u ON s.sender_id = u.id
    WHERE s.recipient_id = ? AND s.status = 'active'
    ORDER BY s.created_at DESC
  `).all(userId) as Array<{
    share_id: string;
    document_id: string;
    wrapped_key_recipient: string;
    ephemeral_public_key_jwk: string;
    shared_at: number;
    sender_username: string;
    document_name: string;
    ciphertext_size: number;
    plaintext_size: number;
    mime_type: string;
    format_version: number;
    file_count: number;
  }>;

  const formatted = shares.map((s) => ({
    ...s,
    ephemeralPublicKeyJwk: JSON.parse(s.ephemeral_public_key_jwk),
  }));

  res.json({ shares: formatted });
});

/**
 * GET /api/sharing/shared-by-me
 * Lists documents shared by the authenticated user to other users.
 */
sharingRouter.get('/shared-by-me', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  const userId = req.user!.id;
  const db = getDatabase();

  const shares = db.prepare(`
    SELECT 
      s.id AS share_id, s.document_id, s.status, s.permission,
      s.created_at AS shared_at,
      u.username AS recipient_username,
      d.name AS document_name, d.ciphertext_size, d.plaintext_size, d.mime_type, d.format_version, d.file_count
    FROM document_shares s
    JOIN documents d ON s.document_id = d.id
    JOIN users u ON s.recipient_id = u.id
    WHERE s.sender_id = ?
    ORDER BY s.created_at DESC
  `).all(userId) as Array<{
    share_id: string;
    document_id: string;
    status: string;
    permission: string;
    shared_at: number;
    recipient_username: string;
    document_name: string;
    ciphertext_size: number;
    plaintext_size: number;
    mime_type: string;
    format_version: number;
    file_count: number;
  }>;

  res.json({ shares });
});

/**
 * POST /api/sharing/revoke
 * Revokes an existing document share.
 */
sharingRouter.post('/revoke', requireAuth, requireCsrf, (req: AuthenticatedRequest, res: Response): void => {
  const userId = req.user!.id;
  const { shareId } = req.body;

  if (!shareId) {
    res.status(400).json({ error: 'Share ID is required.' });
    return;
  }

  const db = getDatabase();

  // Ensure caller is sender or document owner
  const share = db.prepare(`
    SELECT s.id, s.document_id, s.sender_id, d.owner_id
    FROM document_shares s
    JOIN documents d ON s.document_id = d.id
    WHERE s.id = ? AND (s.sender_id = ? OR d.owner_id = ?)
  `).get(shareId, userId, userId);

  if (!share) {
    res.status(404).json({ error: 'Share grant not found or permission denied.' });
    return;
  }

  const now = Date.now();
  db.prepare(`UPDATE document_shares SET status = 'revoked', revoked_at = ? WHERE id = ?`).run(now, shareId);

  res.json({ message: 'Document share grant revoked successfully.' });
});
