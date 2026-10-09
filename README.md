# SecureBox

> **Privacy-first, client-side document protection with authenticated AES-256-GCM encryption, multi-file archive restoration, and SHA-256 integrity verification.**

SecureBox is an open, verifiable web application designed to give users self-sovereign protection over sensitive documents and multi-file collections. All cryptographic operations run 100% locally within the browser’s native Web Crypto API sandbox. No document plaintext, ciphertext, or cryptographic keys are ever transmitted over network boundaries or stored in browser storage.

---

## 1. Core Architecture

```
                      [ User Documents / Folders ]
                                   │
              ┌────────────────────┴────────────────────┐
              ▼                                         ▼
     [ Single or Multi-File ]                  [ Integrity Engine ]
     • 1 File  -> v1 Envelope (.sbox)          • SHA-256 Digest
     • N Files -> v2 Archive  (.sbox)          • Hex Canonicalization
     • 256-bit AES-GCM Key Generation          • Side-by-Side Diff
     • 96-bit Nonce per operation              • Equality Verification
     • Manifest Bound as AAD
     • Zero Unencrypted Disk Artifacts
              │
              ▼
    [ .sbox Encrypted Container ]
    • Magic Bytes: "SBOX"
    • Version: 0x01 (Single) / 0x02 (Archive)
    • Nonce + AAD-Bound Manifest
    • Ciphertext + 128-bit Authentication Tag
              │
              ▼ (Decryption & Authentication)
    • Single: Restores original file directly
    • Archive: Validates per-file SHA-256 digests,
      resolves duplicate paths, and generates a
      downloadable ZIP extracting into a root folder
```

### Module Boundaries
- **`src/core/crypto/`**: Pure functions interfacing directly with `window.crypto.subtle`. Key generation, nonce generation, AES-256-GCM encryption, authenticated decryption, key import/export, and universal decryption routing.
- **`src/core/envelope/`**: Binary serialization and strict byte-level parsing for both `.sbox` single-file (v1) and archive (v2) formats. Enforces bounds checks, magic byte verification, and version negotiation before calling decryption ciphers.
- **`src/core/archive/`**: Multi-file packaging, manifest computation, path sanitization (traversal defense), deduplication, integrity validation, and folder packaging into downloadable ZIP containers via `jszip`.
- **`src/core/hashing/`**: Cryptographic fingerprint generation and comparison utilities.
- **`src/ui/`**: Accessible, high-contrast user interface with strict state machines (`idle` $\rightarrow$ `processing` $\rightarrow$ `success` / `error`). Built without animation bloat or synthetic progress bars, respecting `prefers-reduced-motion`.

---

## 2. Binary Envelope Specifications

### A. Single-File Container (`.sbox` v1)
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

### B. Multi-File Archive Container (`.sbox` v2)
| Offset | Length | Type | Description |
| :--- | :--- | :--- | :--- |
| `0..3` | 4 bytes | ASCII | Magic Bytes: `"SBOX"` (`0x53, 0x42, 0x4F, 0x58`) |
| `4` | 1 byte | uint8 | Format Version (`0x02`) |
| `5` | 1 byte | uint8 | Algorithm Identifier (`0x01` = AES-256-GCM) |
| `6` | 1 byte | uint8 | Nonce Length (`0x0C` = 12 bytes) |
| `7..18` | 12 bytes | bytes | Cryptographically Secure Nonce (IV) |
| `19..22` | 4 bytes | uint32 BE | Manifest Byte Length $M$ (max 1 MiB) |
| `23..N` | $M$ bytes | UTF-8 JSON | Manifest (`{ version, archiveName, fileCount, totalPlaintextSize, files }`) |
| `N+1..` | Variable | bytes | Concatenated File Ciphertext + 128-bit AES-GCM Authentication Tag |

### Additional Authenticated Data (AAD) Protection
In both v1 and v2 formats, the raw UTF-8 bytes of the metadata or manifest header are passed as `additionalData` (AAD) to `crypto.subtle.encrypt`. Any attempt to tamper with filenames, file counts, offsets, or sizes inside the `.sbox` envelope triggers immediate authentication failure during decryption.

---

## 3. Threat Model & Security Posture

### What SecureBox Protects Against
1. **Data Exposure at Rest and in Transit:** Ciphertext cannot be decrypted without the 256-bit AES key.
2. **Ciphertext & Header Tampering:** AES-256-GCM provides authenticated encryption. Flipping a single bit in the ciphertext, IV, tag, or manifest causes decryption to abort.
3. **Archive Truncation & Reordering:** Because the full manifest is bound in AAD and total plain text size is checked, missing, reordered, or truncated archive entries are immediately rejected.
4. **Directory Traversal Attacks:** Input paths are sanitized (e.g., `../../etc/passwd` becomes `etc/passwd`, drive letters stripped).
5. **Silent File Overwrites:** Duplicate filenames in an archive are safely deduplicated (e.g., `file.txt` and `file (1).txt`).
6. **Nonce-Reuse Attacks:** A fresh 96-bit nonce is generated for every encryption call using `crypto.getRandomValues`.
7. **Cloud / Server Eavesdropping:** Zero-knowledge architecture. No server backend, cloud storage, telemetry, or remote logging exists.

### What SecureBox Cannot Protect Against
1. **Compromised Host Environment:** Malware, keyloggers, or rogue extensions running in the user’s browser operating system that inspect memory or keystrokes.
2. **Permanent Key Loss:** There is **no key escrow, password recovery, or backdoor**. If the user loses the key, the encrypted file is permanently unrecoverable.
3. **Identity Verification & Attestation:** Possession of an SHA-256 hash or successful AES-GCM decryption proves mathematical equality and key possession, but does **not** verify who authored, signed, or officially issued the original file.
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
Executes all 49 unit and integration tests across crypto, envelope parsing, archive packing/unpacking, NIST vectors, avalanche effect, and end-to-end workflows.

### Production Build
```bash
npm run build
```
Generates an optimized, statically deployable bundle in `dist/`.
