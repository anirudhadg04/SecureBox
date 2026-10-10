import { Request, Response, NextFunction } from 'express';
import { getDatabase } from './db';
import { hashToken } from './crypto';

export interface AuthenticatedUser {
  id: string;
  username: string;
  email: string;
  role: string;
  storageQuotaBytes: number;
}

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser;
  sessionId?: string;
  csrfToken?: string;
}

const SESSION_COOKIE_NAME = 'sbox_session';
const SESSION_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

export function sessionMiddleware(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const token = req.cookies?.[SESSION_COOKIE_NAME];
  if (!token || typeof token !== 'string') {
    return next();
  }

  const tokenHash = hashToken(token);
  const db = getDatabase();

  const now = Date.now();
  const row = db.prepare(`
    SELECT s.id AS session_id, s.csrf_token, s.expires_at, u.id AS user_id, u.username, u.email, u.role, u.storage_quota_bytes
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.session_token_hash = ? AND s.expires_at > ?
  `).get(tokenHash, now) as {
    session_id: string;
    csrf_token: string;
    expires_at: number;
    user_id: string;
    username: string;
    email: string;
    role: string;
    storage_quota_bytes: number;
  } | undefined;

  if (!row) {
    // Session expired or invalid
    res.clearCookie(SESSION_COOKIE_NAME);
    return next();
  }

  // Update last active
  db.prepare(`UPDATE sessions SET last_active_at = ? WHERE id = ?`).run(now, row.session_id);

  req.user = {
    id: row.user_id,
    username: row.username,
    email: row.email,
    role: row.role,
    storageQuotaBytes: row.storage_quota_bytes,
  };
  req.sessionId = row.session_id;
  req.csrfToken = row.csrf_token;

  next();
}

/**
 * Enforces that user is authenticated with a valid session.
 */
export function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  next();
}

/**
 * Enforces CSRF token protection on state-changing methods (POST, PUT, PATCH, DELETE).
 */
export function requireCsrf(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const clientCsrfToken = req.headers['x-securebox-csrf'] || req.body?.csrfToken;
  if (!clientCsrfToken || !req.csrfToken || clientCsrfToken !== req.csrfToken) {
    res.status(403).json({ error: 'Invalid or missing CSRF token' });
    return;
  }

  next();
}

/**
 * Lightweight rate-limiting map in memory.
 */
const rateLimitStore = new Map<string, { count: number; resetTime: number }>();

export function createRateLimiter(windowMs: number, maxRequests: number, message = 'Too many requests, please try again later.') {
  return (req: Request, res: Response, next: NextFunction): void => {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const key = `${req.path}:${ip}`;
    const now = Date.now();

    const record = rateLimitStore.get(key);
    if (!record || now > record.resetTime) {
      rateLimitStore.set(key, { count: 1, resetTime: now + windowMs });
      return next();
    }

    record.count++;
    if (record.count > maxRequests) {
      res.status(429).json({ error: message });
      return;
    }

    next();
  };
}

export { SESSION_COOKIE_NAME, SESSION_MAX_AGE_MS };
