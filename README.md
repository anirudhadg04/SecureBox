# SecureBox

> **Privacy-first, client-side document protection with authenticated AES-256-GCM encryption and SHA-256 integrity verification.**

SecureBox is an open, verifiable web tool designed to give users self-sovereign protection over sensitive documents. All cryptographic operations run 100% locally within the browser’s native Web Crypto API sandbox. No document plaintext, ciphertext, or cryptographic keys are ever transmitted over network boundaries or stored in browser storage.

---

## 1. Core Architecture

```
                       [ User Document ]
                              │
               ┌──────────────┴──────────────┐
               ▼                             ▼
       [ Encrypt Pipeline ]          [ Integrity Engine ]
       • Generate 256-bit Key        • SHA-256 Digest
       • Generate 96-bit Nonce       • Hex Canonicalization
       • Bind Metadata via AAD       • Side-by-Side Diff
       • AES-256-GCM Auth Encrypt    • Equality Verification
               │
               ▼
     [ .sbox Binary Envelope ]
     • Magic Bytes ("SBOX")
     • Format Version (0x01)
     • Algorithm ID (AES-256-GCM)
     • Nonce + Bound Metadata
     • Ciphertext + 128-bit Tag
```

### Module Boundaries
- **`src/core/crypto/`**: Pure functions interfacing directly with `window.crypto.subtle`. Key generation, nonce generation, AES-256-GCM encryption, authenticated decryption, and key import/export. Zero DOM or React coupling; 100% testable in isolation.
- **`src/core/envelope/`**: Binary serialization and strict byte-level parsing for the `.sbox` container format. Enforces bounds checks, magic byte verification, and version negotiation before calling decryption ciphers.
- **`src/core/hashing/`**: Cryptographic fingerprint generation and comparison utilities.
- **`src/ui/`**: Accessible, high-contrast user interface with strict state machines (`idle` $\rightarrow$ `processing` $\rightarrow$ `success` / `error`). Built without animation bloat or synthetic progress bars, respecting `prefers-reduced-motion`.

---

## 2. Binary Envelope Specification (`.sbox` v1)

Files are stored and distributed as self-contained `.sbox` binary containers:

| Offset | Length | Type | Description |
| :--- | :--- | :--- | :--- |
| `0..3` | 4 bytes | ASCII | Magic Bytes: `"SBOX"` (`0x53, 0x42, 0x4F, 0x58`) |
| `4` | 1 byte | uint8 | Format Version (`0x01`) |
| `5` | 1 byte | uint8 | Algorithm Identifier (`0x01` = AES-256-GCM) |
| `6` | 1 byte | uint8 | Nonce Length (`0x0C` = 12 bytes) |
| `7..18` | 12 bytes | bytes | Cryptographically Secure Nonce (IV) |
| `19..20` | 2 bytes | uint16 BE | Metadata Byte Length $M$ (max 4096 bytes) |
| `21..N` | $M$ bytes | UTF-8 JSON | Metadata (`{ originalName, mimeType, size, createdAt }`) |
| `N+1..` | Variable | bytes | Ciphertext + 128-bit AES-GCM Authentication Tag |

### Additional Authenticated Data (AAD) Protection
During encryption, the raw UTF-8 bytes of the metadata header are passed as `additionalData` (AAD) to `crypto.subtle.encrypt`. Any attempt to tamper with the filename, MIME type, or metadata inside the `.sbox` file causes the authentication tag verification to fail during decryption, preventing header-spoofing attacks.

---

## 3. Threat Model

### What SecureBox Protects Against
1. **Data Exposure at Rest and in Transit:** The document ciphertext cannot be decrypted without the 256-bit AES key.
2. **Ciphertext & Header Tampering:** AES-256-GCM provides authenticated encryption. Flipping a single bit in the ciphertext, IV, tag, or header metadata causes decryption to abort.
3. **Nonce-Reuse Attacks:** A fresh 96-bit nonce is generated for every encryption call using `crypto.getRandomValues`.
4. **Cloud / Server Eavesdropping:** Zero-knowledge architecture. No server backend, cloud storage, telemetry, or remote logging exists.
5. **Accidental Bit-Rot & Silent Corruption:** Independent SHA-256 fingerprinting exposes transmission alterations or accidental corruption.

### What SecureBox Cannot Protect Against
1. **Compromised Host Environment:** Malware, keyloggers, or rogue extensions running in the user’s browser operating system that inspect memory or keystrokes.
2. **Permanent Key Loss:** There is **no key escrow, password recovery, or backdoor**. If the user loses the key, the encrypted file is permanently unrecoverable.
3. **Identity Verification & Attestation:** Possession of an SHA-256 hash or successful AES-GCM decryption proves mathematical equality and key possession, but does **not** verify who authored, signed, or officially issued the original file (no Public Key Infrastructure or digital signatures).
4. **Physical Screen Exposure:** Plaintext visible on screen before encryption or after decryption.

---

## 4. Getting Started

### Prerequisites
- Node.js `v20.0.0` or higher
- npm `10.0.0` or higher

### Installation
```bash
git clone <repository-url>
cd SecureBox
npm install
```

### Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

### Run Automated Tests
```bash
npm test
```
Executes all 35 unit and integration tests across crypto, envelope parsing, NIST vectors, avalanche effect, and end-to-end workflows.

### Production Build
```bash
npm run build
```
Generates an optimized, statically deployable bundle in `dist/`.

---

## 5. Security & Verification Guarantees

- **No Roll-Your-Own Crypto:** Standard W3C Web Cryptography API (`crypto.subtle`) backed by OS/hardware AES-NI instructions.
- **Zero In-Memory Storage Leakage:** Keys are held in transient memory only during active operations. No `localStorage`, `sessionStorage`, cookies, or URL parameters are utilized.
- **No Progress Fabrication:** The interface uses honest, indeterminate status indicators during asynchronous operations without artificial progress bars.
