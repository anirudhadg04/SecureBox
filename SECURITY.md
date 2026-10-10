# SecureBox Security Specification & Threat Model

## 1. Executive Summary & Philosophy
**SecureBox** is a privacy-first, zero-knowledge document protection vault and encrypted sharing platform. The core architectural tenet of SecureBox is that **data confidentiality and integrity do not depend on trusting the server or database**. Plaintext documents and raw decryption keys are never transmitted over the network or stored unencrypted on the backend.

---

## 2. Cryptographic Architecture

### A. Document Encryption (.sbox v1 and v2 formats)
- **Algorithm**: Authenticated AES-256-GCM (`crypto.subtle`) via the native browser Web Crypto API.
- **Nonce Generation**: 96-bit cryptographically secure random initialization vector (`crypto.getRandomValues`) freshly generated for every encryption operation. Nonces are never reused.
- **Authentication**: 128-bit authentication tag appended to the ciphertext.
- **Associated Data Binding (AAD)**: Archive manifests and document metadata are serialized into UTF-8 JSON and passed as Additional Authenticated Data (`additionalData`) to AES-GCM. Any modification or tampering with metadata immediately fails cryptographic authentication before plaintext buffers are released.
- **Integrity Fingerprints**: Every file in a multi-file collection archive is independently hashed using SHA-256 (`crypto.subtle.digest`) and verified upon decryption.

### B. Recipient-Bound Asymmetric Sharing (ECDH P-256 + HKDF + AES-GCM)
- **Key Agreement**: NIST P-256 Elliptic Curve Diffie-Hellman (ECDH) via Web Crypto.
- **Protocol**:
  1. The recipient publishes their verified ECDH public key (JWK format) to the SecureBox server.
  2. When User A shares a document with User B, User A generates an ephemeral P-256 keypair in the browser.
  3. User A computes the ECDH shared secret between the ephemeral private key and User B's public key.
  4. User A derives a 256-bit AES-GCM wrapping key via HKDF (SHA-256) bound cryptographically to contextual metadata (`doc:<id>:recipient:<userId>:v1`).
  5. The document's raw 256-bit AES key is encrypted/wrapped and uploaded alongside the ephemeral public key.
  6. Only User B's private key can unwrap the decryption key. The server never learns the raw document key.

---

## 3. OWASP Top 10:2025 Risk Mitigation Mapping

| OWASP Risk Category | SecureBox Security Control Implementation |
|---|---|
| **A01: Broken Access Control** | • Deny-by-default server-side authorization on all routes.<br>• Strict object-level access control queries preventing IDOR/BOLA.<br>• Cascade database foreign keys removing orphaned access grants upon deletion. |
| **A02: Cryptographic Failures** | • Client-side authenticated AES-256-GCM with fresh nonces.<br>• Recipient-bound ECDH key agreement with HKDF context binding.<br>• No raw keys in URLs, database columns, or server logs. |
| **A03: Injection** | • Parameterized SQL queries using `better-sqlite3` prepared statements.<br>• Strict input validation on usernames, emails, and numeric manifest bounds. |
| **A04: Insecure Design** | • Zero-knowledge threat model: compromised backend database exposes only encrypted `.sbox` ciphertext and wrapped keys. |
| **A05: Security Misconfiguration** | • Security headers enabled (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`).<br>• Local development database and uploaded documents excluded from Git via `.gitignore`. |
| **A06: Vulnerable and Outdated Components** | • Regular dependency audit and zero vulnerable runtime packages in the core crypto pipeline. |
| **A07: Identification and Authentication Failures** | • Passwords hashed with PBKDF2-SHA512 (600,000 iterations, 32-byte salts).<br>• Generic authentication error messages to prevent account enumeration.<br>• Timing-safe password verification comparisons.<br>• In-memory rate limiting on `/api/auth/*` (10 requests/min).<br>• 256-bit secure session tokens stored as SHA-256 hashes.<br>• `HttpOnly`, `SameSite=Strict` cookies with anti-CSRF token verification (`X-SecureBox-CSRF`). |
| **A08: Software and Data Integrity Failures** | • Archive manifest contiguous range validation, NTFS case-folding deduplication, and SHA-256 digest checks preventing tampering. |
| **A09: Security Logging and Alerting Failures** | • Structured audit log table recording access and administrative events without logging sensitive keys or payloads. |
| **A10: Mishandling of Exceptional Conditions** | • Strict typed envelope errors (`InvalidMagicBytesError`, `ArchiveIntegrityMismatchError`) failing closed and releasing no unauthenticated plaintext. |

---

## 4. Local Deployment Instructions

1. **Install Dependencies**:
   ```bash
   npm install
   ```

2. **Configure Environment Variables**:
   Copy the example environment configuration:
   ```bash
   cp .env.example .env
   ```

3. **Run Automated Test Suite**:
   ```bash
   npm test
   ```

4. **Build Production Bundle**:
   ```bash
   npm run build
   ```

5. **Start Local Development Server**:
   ```bash
   # Starts Vite frontend
   npm run dev
   ```

---

## 5. Trust Model & DigiLocker Comparison
SecureBox provides client-side zero-knowledge document encryption and recipient-bound key delivery. 
- In contrast to services like DigiLocker (which serve as state-authorized identity repositories relying on centralized server verification and mobile OTPs), SecureBox operates under a cryptographic zero-knowledge trust model. 
- **Limitation**: If a user loses their private document key or master vault secret, SecureBox cannot recover the document on their behalf.
