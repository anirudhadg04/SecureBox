import { Router, Response } from 'express';
import { getDatabase } from '../db';
import { generateSecureToken, generateUuid, hashPassword, hashToken, verifyPassword } from '../crypto';
import {
  AuthenticatedRequest,
  createRateLimiter,
  requireAuth,
  requireCsrf,
  SESSION_COOKIE_NAME,
  SESSION_MAX_AGE_MS,
} from '../middleware';

export const authRouter = Router();

// Rate limiter for auth attempts: max 10 requests per minute per IP
const authLimiter = createRateLimiter(60 * 1000, 10, 'Too many authentication attempts. Please wait a minute.');

// Helper to set session cookie
function setSessionCookie(res: Response, token: string): void {
  const isProduction = process.env.NODE_ENV === 'production';
  res.cookie(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    maxAge: SESSION_MAX_AGE_MS,
    path: '/',
  });
}

/**
 * POST /api/auth/register
 */
authRouter.post('/register', authLimiter, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const { username, email, password } = req.body;

  if (!username || typeof username !== 'string' || username.trim().length < 3 || username.trim().length > 32) {
    res.status(400).json({ error: 'Username must be between 3 and 32 characters.' });
    return;
  }
  if (!email || typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    res.status(400).json({ error: 'A valid email address is required.' });
    return;
  }
  if (!password || typeof password !== 'string' || password.length < 8 || password.length > 128) {
    res.status(400).json({ error: 'Password must be between 8 and 128 characters.' });
    return;
  }

  const cleanUsername = username.trim();
  const cleanEmail = email.trim().toLowerCase();
  const db = getDatabase();

  // Check unique username and email
  const existing = db.prepare(`SELECT id FROM users WHERE username = ? OR email = ?`).get(cleanUsername, cleanEmail);
  if (existing) {
    // Generic response to prevent account enumeration
    res.status(400).json({ error: 'Username or email is already registered.' });
    return;
  }

  try {
    const { hash, salt } = await hashPassword(password);
    const userId = generateUuid();
    const now = Date.now();

    db.prepare(`
      INSERT INTO users (id, username, email, password_hash, password_salt, role, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, 'user', ?, ?)
    `).run(userId, cleanUsername, cleanEmail, hash, salt, now, now);

    // Create session
    const sessionToken = generateSecureToken();
    const tokenHash = hashToken(sessionToken);
    const csrfToken = generateSecureToken();
    const sessionId = generateUuid();

    db.prepare(`
      INSERT INTO sessions (id, user_id, session_token_hash, csrf_token, expires_at, created_at, last_active_at, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      sessionId,
      userId,
      tokenHash,
      csrfToken,
      now + SESSION_MAX_AGE_MS,
      now,
      now,
      req.ip || 'unknown',
      req.headers['user-agent'] || 'unknown'
    );

    setSessionCookie(res, sessionToken);

    res.status(201).json({
      user: {
        id: userId,
        username: cleanUsername,
        email: cleanEmail,
        role: 'user',
        storageQuotaBytes: 104857600,
      },
      csrfToken,
    });
  } catch {
    res.status(500).json({ error: 'Failed to create user account.' });
  }
});

/**
 * POST /api/auth/login
 */
authRouter.post('/login', authLimiter, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const { identifier, password } = req.body;

  if (!identifier || typeof identifier !== 'string' || !password || typeof password !== 'string') {
    res.status(400).json({ error: 'Invalid credentials.' });
    return;
  }

  const cleanIdentifier = identifier.trim().toLowerCase();
  const db = getDatabase();

  try {
    const user = db.prepare(`
      SELECT id, username, email, password_hash, password_salt, role, storage_quota_bytes
      FROM users
      WHERE lower(username) = ? OR lower(email) = ?
    `).get(cleanIdentifier, cleanIdentifier) as {
      id: string;
      username: string;
      email: string;
      password_hash: string;
      password_salt: string;
      role: string;
      storage_quota_bytes: number;
    } | undefined;

    if (!user) {
      // Always perform a dummy comparison to mitigate timing attacks
      await verifyPassword(password, '00'.repeat(32), '00'.repeat(64));
      res.status(401).json({ error: 'Invalid username/email or password.' });
      return;
    }

    const isValid = await verifyPassword(password, user.password_salt, user.password_hash);
    if (!isValid) {
      res.status(401).json({ error: 'Invalid username/email or password.' });
      return;
    }

    // Rotate session: generate fresh session token & CSRF token
    const sessionToken = generateSecureToken();
    const tokenHash = hashToken(sessionToken);
    const csrfToken = generateSecureToken();
    const sessionId = generateUuid();
    const now = Date.now();

    db.prepare(`
      INSERT INTO sessions (id, user_id, session_token_hash, csrf_token, expires_at, created_at, last_active_at, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      sessionId,
      user.id,
      tokenHash,
      csrfToken,
      now + SESSION_MAX_AGE_MS,
      now,
      now,
      req.ip || 'unknown',
      req.headers['user-agent'] || 'unknown'
    );

    setSessionCookie(res, sessionToken);

    res.json({
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        storageQuotaBytes: user.storage_quota_bytes,
      },
      csrfToken,
    });
  } catch {
    res.status(500).json({ error: 'Internal authentication error. Please try again later.' });
  }
});

/**
 * POST /api/auth/logout
 */
authRouter.post('/logout', requireAuth, requireCsrf, (req: AuthenticatedRequest, res: Response): void => {
  if (req.sessionId) {
    const db = getDatabase();
    db.prepare(`DELETE FROM sessions WHERE id = ?`).run(req.sessionId);
  }
  res.clearCookie(SESSION_COOKIE_NAME, { path: '/' });
  res.json({ message: 'Logged out successfully.' });
});

/**
 * GET /api/auth/me
 */
authRouter.get('/me', (req: AuthenticatedRequest, res: Response): void => {
  if (!req.user) {
    res.status(401).json({ user: null });
    return;
  }
  res.json({
    user: req.user,
    csrfToken: req.csrfToken,
  });
});

/**
 * POST /api/auth/forgot-password
 */
authRouter.post('/forgot-password', authLimiter, (req: AuthenticatedRequest, res: Response): void => {
  const { email } = req.body;
  // Always return identical generic success message to prevent account enumeration
  const genericSuccess = 'If an account matches that email, a password reset token has been generated.';

  if (!email || typeof email !== 'string') {
    res.json({ message: genericSuccess });
    return;
  }

  const cleanEmail = email.trim().toLowerCase();
  const db = getDatabase();
  const user = db.prepare(`SELECT id FROM users WHERE lower(email) = ?`).get(cleanEmail) as { id: string } | undefined;

  if (user) {
    const rawResetToken = generateSecureToken();
    const tokenHash = hashToken(rawResetToken);
    const resetId = generateUuid();
    const now = Date.now();
    const expiresAt = now + 15 * 60 * 1000; // 15 minutes

    db.prepare(`
      INSERT INTO password_resets (id, user_id, token_hash, expires_at, used, created_at)
      VALUES (?, ?, ?, ?, 0, ?)
    `).run(resetId, user.id, tokenHash, expiresAt, now);

    // In local development, return the token for testing purposes if not production
    if (process.env.NODE_ENV !== 'production') {
      res.json({ message: genericSuccess, devResetToken: rawResetToken });
      return;
    }
  }

  res.json({ message: genericSuccess });
});

/**
 * POST /api/auth/reset-password
 */
authRouter.post('/reset-password', authLimiter, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  const { token, newPassword } = req.body;

  if (!token || typeof token !== 'string' || !newPassword || typeof newPassword !== 'string' || newPassword.length < 8) {
    res.status(400).json({ error: 'Valid reset token and password (min 8 chars) required.' });
    return;
  }

  const tokenHash = hashToken(token);
  const db = getDatabase();
  const now = Date.now();

  const reset = db.prepare(`
    SELECT id, user_id, expires_at, used FROM password_resets WHERE token_hash = ?
  `).get(tokenHash) as { id: string; user_id: string; expires_at: number; used: number } | undefined;

  if (!reset || reset.used === 1 || now > reset.expires_at) {
    res.status(400).json({ error: 'Reset token is invalid, expired, or already used.' });
    return;
  }

  try {
    const { hash, salt } = await hashPassword(newPassword);

    // Update password, mark token used, invalidate all active sessions
    const update = db.transaction(() => {
      db.prepare(`UPDATE users SET password_hash = ?, password_salt = ?, updated_at = ? WHERE id = ?`).run(
        hash,
        salt,
        now,
        reset.user_id
      );
      db.prepare(`UPDATE password_resets SET used = 1 WHERE id = ?`).run(reset.id);
      db.prepare(`DELETE FROM sessions WHERE user_id = ?`).run(reset.user_id);
    });
    update();

    res.json({ message: 'Password has been reset successfully. Please log in with your new password.' });
  } catch {
    res.status(500).json({ error: 'Failed to reset password.' });
  }
});
