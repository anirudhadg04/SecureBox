import { Router, Response } from 'express';
import fs from 'fs';
import path from 'path';
import { getDatabase } from '../db';
import { generateUuid } from '../crypto';
import { AuthenticatedRequest, requireAuth, requireCsrf } from '../middleware';

export const documentsRouter = Router();

function getStorageDir(): string {
  const dir = process.env.VAULT_STORAGE_DIR || './data/vault_storage';
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return dir;
}

/**
 * GET /api/documents
 * Lists all documents belonging to the authenticated user.
 */
documentsRouter.get('/', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  const userId = req.user!.id;
  const db = getDatabase();

  const docs = db.prepare(`
    SELECT 
      d.id, d.name, d.ciphertext_size, d.plaintext_size, d.mime_type, d.format_version,
      d.file_count, d.sha256_ciphertext, d.wrapped_key_owner, d.created_at, d.updated_at,
      (SELECT COUNT(*) FROM document_shares s WHERE s.document_id = d.id AND s.status = 'active') AS active_shares_count
    FROM documents d
    WHERE d.owner_id = ?
    ORDER BY d.created_at DESC
  `).all(userId);

  // Storage usage calculation
  const usageRow = db.prepare(`
    SELECT COALESCE(SUM(ciphertext_size), 0) AS total_used FROM documents WHERE owner_id = ?
  `).get(userId) as { total_used: number };

  res.json({
    documents: docs,
    usageBytes: usageRow.total_used,
    quotaBytes: req.user!.storageQuotaBytes,
  });
});

/**
 * POST /api/documents
 * Ingests an encrypted .sbox file into the user's private vault.
 * Expects JSON payload with:
 * - name: string
 * - ciphertextBase64: string (the encrypted .sbox bytes)
 * - plaintextSize: number
 * - mimeType: string
 * - formatVersion: 1 | 2
 * - fileCount: number
 * - sha256Ciphertext: string
 * - wrappedKeyOwner: string
 */
documentsRouter.post('/', requireAuth, requireCsrf, (req: AuthenticatedRequest, res: Response): void => {
  const userId = req.user!.id;
  const {
    name,
    ciphertextBase64,
    plaintextSize,
    mimeType,
    formatVersion,
    fileCount = 1,
    sha256Ciphertext,
    wrappedKeyOwner,
  } = req.body;

  if (!name || typeof name !== 'string') {
    res.status(400).json({ error: 'Valid document name required.' });
    return;
  }
  if (!ciphertextBase64 || typeof ciphertextBase64 !== 'string') {
    res.status(400).json({ error: 'Encrypted ciphertext payload required.' });
    return;
  }
  if (!wrappedKeyOwner || typeof wrappedKeyOwner !== 'string') {
    res.status(400).json({ error: 'Wrapped vault key required.' });
    return;
  }

  // Decode buffer
  let cipherBuffer: Buffer;
  try {
    cipherBuffer = Buffer.from(ciphertextBase64, 'base64');
  } catch {
    res.status(400).json({ error: 'Invalid base64 payload.' });
    return;
  }

  const ciphertextSize = cipherBuffer.length;
  const db = getDatabase();

  // Storage quota check
  const usageRow = db.prepare(`
    SELECT COALESCE(SUM(ciphertext_size), 0) AS total_used FROM documents WHERE owner_id = ?
  `).get(userId) as { total_used: number };

  if (usageRow.total_used + ciphertextSize > req.user!.storageQuotaBytes) {
    res.status(413).json({ error: 'Storage quota exceeded. Please free up space before uploading.' });
    return;
  }

  // Save to disk
  const docId = generateUuid();
  const storageDir = getStorageDir();
  const filePath = path.join(storageDir, `${docId}.sbox`);

  try {
    fs.writeFileSync(filePath, cipherBuffer);
  } catch {
    res.status(500).json({ error: 'Failed to write document to vault storage.' });
    return;
  }

  const now = Date.now();
  db.prepare(`
    INSERT INTO documents (
      id, owner_id, name, ciphertext_size, plaintext_size, mime_type, format_version,
      file_count, storage_path, sha256_ciphertext, wrapped_key_owner, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    docId,
    userId,
    name.trim(),
    ciphertextSize,
    Number.isSafeInteger(plaintextSize) ? plaintextSize : ciphertextSize,
    mimeType || 'application/octet-stream',
    formatVersion === 2 ? 2 : 1,
    fileCount,
    filePath,
    sha256Ciphertext || '',
    wrappedKeyOwner,
    now,
    now
  );

  res.status(201).json({
    id: docId,
    name: name.trim(),
    ciphertextSize,
    formatVersion,
    createdAt: now,
  });
});

/**
 * GET /api/documents/:id/download
 * Downloads the encrypted .sbox ciphertext artifact for client decryption.
 */
documentsRouter.get('/:id/download', requireAuth, (req: AuthenticatedRequest, res: Response): void => {
  const userId = req.user!.id;
  const docId = req.params.id;
  const db = getDatabase();

  // Object-level authorization: owner OR active share recipient
  const doc = db.prepare(`
    SELECT d.id, d.name, d.storage_path, d.wrapped_key_owner, d.owner_id
    FROM documents d
    WHERE d.id = ? AND (
      d.owner_id = ? OR 
      EXISTS (SELECT 1 FROM document_shares s WHERE s.document_id = d.id AND s.recipient_id = ? AND s.status = 'active')
    )
  `).get(docId, userId, userId) as {
    id: string;
    name: string;
    storage_path: string;
    wrapped_key_owner: string;
    owner_id: string;
  } | undefined;

  if (!doc) {
    res.status(404).json({ error: 'Document not found or access denied.' });
    return;
  }

  if (!fs.existsSync(doc.storage_path)) {
    res.status(404).json({ error: 'Stored document artifact is missing on server.' });
    return;
  }

  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(doc.name)}.sbox"`);
  const stream = fs.createReadStream(doc.storage_path);
  stream.pipe(res);
});

/**
 * DELETE /api/documents/:id
 * Permanently deletes the document artifact and records.
 */
documentsRouter.delete('/:id', requireAuth, requireCsrf, (req: AuthenticatedRequest, res: Response): void => {
  const userId = req.user!.id;
  const docId = req.params.id;
  const db = getDatabase();

  // Strict ownership check
  const doc = db.prepare(`SELECT id, storage_path FROM documents WHERE id = ? AND owner_id = ?`).get(docId, userId) as {
    id: string;
    storage_path: string;
  } | undefined;

  if (!doc) {
    res.status(404).json({ error: 'Document not found or access denied.' });
    return;
  }

  // Remove file from disk
  if (fs.existsSync(doc.storage_path)) {
    try {
      fs.unlinkSync(doc.storage_path);
    } catch {
      // Continue to remove DB entry even if disk file error
    }
  }

  // Cascade delete cleans up document_shares
  db.prepare(`DELETE FROM documents WHERE id = ?`).run(docId);

  res.json({ message: 'Document permanently deleted from vault.' });
});
