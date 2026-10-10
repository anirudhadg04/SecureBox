import crypto from 'crypto';

const PBKDF2_ITERATIONS = 600000;
const PBKDF2_KEY_LEN = 64;
const PBKDF2_DIGEST = 'sha512';

/**
 * Hashes a password with a fresh cryptographically random 32-byte salt using PBKDF2-SHA512
 * configured with 600,000 iterations (OWASP recommendation for password storage).
 */
export async function hashPassword(password: string): Promise<{ hash: string; salt: string }> {
  return new Promise((resolve, reject) => {
    const saltBytes = crypto.randomBytes(32);
    const salt = saltBytes.toString('hex');

    crypto.pbkdf2(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LEN, PBKDF2_DIGEST, (err, derivedKey) => {
      if (err) return reject(err);
      resolve({
        hash: derivedKey.toString('hex'),
        salt,
      });
    });
  });
}

/**
 * Verifies a supplied password against a known salt and hash using timing-safe comparison.
 */
export async function verifyPassword(password: string, salt: string, expectedHash: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LEN, PBKDF2_DIGEST, (err, derivedKey) => {
      if (err) return reject(err);
      const computedBuffer = Buffer.from(derivedKey.toString('hex'), 'hex');
      const expectedBuffer = Buffer.from(expectedHash, 'hex');

      if (computedBuffer.length !== expectedBuffer.length) {
        return resolve(false);
      }
      resolve(crypto.timingSafeEqual(computedBuffer, expectedBuffer));
    });
  });
}

/**
 * Computes a SHA-256 hash of a session token for storage in the database.
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Generates a 256-bit cryptographically secure random session token.
 */
export function generateSecureToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Generates a random UUID v4.
 */
export function generateUuid(): string {
  return crypto.randomUUID();
}
