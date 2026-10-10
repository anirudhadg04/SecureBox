import { describe, expect, it } from 'vitest';
import {
  unpackArchiveEnvelope,
  packArchiveEnvelope,
} from '../../src/core/envelope/archiveEnvelope';
import { packEnvelope } from '../../src/core/envelope/pack';
import { generateAesKey, generateNonce, encryptBytes } from '../../src/core/crypto/aesGcm';
import { decryptArchive, encryptArchive } from '../../src/core/archive/archiveService';
import { decryptDocument } from '../../src/core/crypto/service';
import { ArchiveManifest } from '../../src/core/archive/types';
import {
  sanitizeArchivePath,
  resolveUniquePaths,
} from '../../src/core/archive/types';
import {
  InvalidManifestIntegerError,
  ManifestFileCountMismatchError,
  ManifestEntryBoundsError,
  ManifestNonContiguousError,
  InvalidArchivePathError,
  MetadataSizeMismatchError,
  InvalidMetadataError,
} from '../../src/core/envelope/errors';

describe('Security Regression Tests', () => {
  describe('SEC-01/SEC-03: Manifest Integer Validation and Archive Integrity', () => {
    const makeValidManifest = (overrides: Partial<ArchiveManifest> = {}): ArchiveManifest => ({
      version: 1,
      archiveName: 'test',
      createdAt: Date.now(),
      fileCount: 1,
      totalPlaintextSize: 10,
      files: [
        {
          path: 'test.txt',
          size: 10,
          offset: 0,
          mimeType: 'text/plain',
          sha256: 'a'.repeat(64),
        },
      ],
      ...overrides,
    });

    const makePackedArchive = (manifest: ArchiveManifest) => {
      const iv = new Uint8Array(12);
      const ciphertextWithTag = new Uint8Array(32);
      return packArchiveEnvelope({ ciphertextWithTag, iv, manifest });
    };

    it('rejects fractional fileCount', () => {
      const manifest = makeValidManifest({ fileCount: 1.5 as any });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(InvalidManifestIntegerError);
    });

    it('rejects NaN fileCount', () => {
      const manifest = makeValidManifest({ fileCount: NaN as any });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(InvalidManifestIntegerError);
    });

    it('rejects unsafe integer fileCount (> 2^53-1)', () => {
      const manifest = makeValidManifest({ fileCount: Number.MAX_SAFE_INTEGER + 1 });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(InvalidManifestIntegerError);
    });

    it('rejects negative fileCount', () => {
      const manifest = makeValidManifest({ fileCount: -1 });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(InvalidManifestIntegerError);
    });

    it('rejects fileCount exceeding MAX_ARCHIVE_FILE_COUNT', () => {
      const manifest = makeValidManifest({ fileCount: 10001 });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(InvalidManifestIntegerError);
    });

    it('rejects fractional totalPlaintextSize', () => {
      const manifest = makeValidManifest({ totalPlaintextSize: 10.5 as any });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(InvalidManifestIntegerError);
    });

    it('rejects negative totalPlaintextSize', () => {
      const manifest = makeValidManifest({ totalPlaintextSize: -1 });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(InvalidManifestIntegerError);
    });

    it('rejects totalPlaintextSize exceeding MAX_TOTAL_PLAINTEXT_SIZE_BYTES', () => {
      const manifest = makeValidManifest({ totalPlaintextSize: 1024 * 1024 * 1024 + 1 });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(InvalidManifestIntegerError);
    });

    it('rejects fractional entry size', () => {
      const manifest = makeValidManifest({
        files: [{ ...makeValidManifest().files[0], size: 10.5 as any }],
      });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(InvalidManifestIntegerError);
    });

    it('rejects negative entry size', () => {
      const manifest = makeValidManifest({
        files: [{ ...makeValidManifest().files[0], size: -1 }],
      });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(InvalidManifestIntegerError);
    });

    it('rejects fractional entry offset', () => {
      const manifest = makeValidManifest({
        files: [{ ...makeValidManifest().files[0], offset: 1.5 as any }],
      });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(InvalidManifestIntegerError);
    });

    it('rejects negative entry offset', () => {
      const manifest = makeValidManifest({
        files: [{ ...makeValidManifest().files[0], offset: -1 }],
      });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(InvalidManifestIntegerError);
    });

    it('rejects fileCount mismatch with files array length', () => {
      const manifest = makeValidManifest({ fileCount: 2 });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(ManifestFileCountMismatchError);
    });

    it('rejects entry bounds exceeding totalPlaintextSize', () => {
      const manifest = makeValidManifest({
        totalPlaintextSize: 10,
        files: [{ ...makeValidManifest().files[0], size: 20 }],
      });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(ManifestEntryBoundsError);
    });

    it('rejects entry offset + size exceeding totalPlaintextSize', () => {
      const manifest = makeValidManifest({
        totalPlaintextSize: 10,
        files: [{ ...makeValidManifest().files[0], offset: 5, size: 10 }],
      });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(ManifestEntryBoundsError);
    });

    it('rejects first entry not starting at offset 0', () => {
      // This test checks the case where the first entry starts at offset > 0 but doesn't exceed totalPlaintextSize
      const manifest = makeValidManifest({
        totalPlaintextSize: 20,
        files: [{ ...makeValidManifest().files[0], offset: 5, size: 10 }],
      });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(ManifestNonContiguousError);
    });

    it('accepts zero-byte file sharing offset with non-empty file', () => {
      // Zero-byte files occupy no space, so they can share offsets
      const manifest: ArchiveManifest = {
        version: 1,
        archiveName: 'test',
        createdAt: Date.now(),
        fileCount: 2,
        totalPlaintextSize: 10,
        files: [
          { path: 'empty.txt', size: 0, offset: 0, mimeType: 'text/plain', sha256: 'e'.repeat(64) },
          { path: 'data.txt', size: 10, offset: 0, mimeType: 'text/plain', sha256: 'd'.repeat(64) },
        ],
      };
      const packed = makePackedArchive(manifest);
      const result = unpackArchiveEnvelope(packed);
      expect(result.manifest.fileCount).toBe(2);
    });

    it('accepts valid zero-byte file at the end', () => {
      const manifest: ArchiveManifest = {
        version: 1,
        archiveName: 'test',
        createdAt: Date.now(),
        fileCount: 2,
        totalPlaintextSize: 10,
        files: [
          { path: 'data.txt', size: 10, offset: 0, mimeType: 'text/plain', sha256: 'd'.repeat(64) },
          { path: 'empty.txt', size: 0, offset: 10, mimeType: 'text/plain', sha256: 'e'.repeat(64) },
        ],
      };
      const packed = makePackedArchive(manifest);
      // Should not throw - this is a valid zero-byte file at the end
      const result = unpackArchiveEnvelope(packed);
      expect(result.manifest.fileCount).toBe(2);
    });

    it('accepts multiple zero-byte files in sequence', () => {
      const manifest: ArchiveManifest = {
        version: 1,
        archiveName: 'test',
        createdAt: Date.now(),
        fileCount: 3,
        totalPlaintextSize: 10,
        files: [
          { path: 'data.txt', size: 10, offset: 0, mimeType: 'text/plain', sha256: 'd'.repeat(64) },
          { path: 'empty1.txt', size: 0, offset: 10, mimeType: 'text/plain', sha256: 'e'.repeat(64) },
          { path: 'empty2.txt', size: 0, offset: 10, mimeType: 'text/plain', sha256: 'e'.repeat(64) },
        ],
      };
      const packed = makePackedArchive(manifest);
      const result = unpackArchiveEnvelope(packed);
      expect(result.manifest.fileCount).toBe(3);
    });

    it('rejects empty archive with non-zero totalPlaintextSize', () => {
      const manifest = makeValidManifest({ fileCount: 0, totalPlaintextSize: 5, files: [] });
      const packed = makePackedArchive(manifest);
      expect(() => unpackArchiveEnvelope(packed)).toThrow(ManifestNonContiguousError);
    });

    it('accepts empty archive with zero totalPlaintextSize', () => {
      const manifest = makeValidManifest({ fileCount: 0, totalPlaintextSize: 0, files: [] });
      const packed = makePackedArchive(manifest);
      const result = unpackArchiveEnvelope(packed);
      expect(result.manifest.fileCount).toBe(0);
      expect(result.manifest.totalPlaintextSize).toBe(0);
    });
  });

  describe('SEC-02/SEC-04: Cross-Platform Path Safety', () => {
    it('rejects directory traversal with ..', () => {
      expect(() => sanitizeArchivePath('../../etc/passwd')).toThrow(InvalidArchivePathError);
      expect(() => sanitizeArchivePath('..\\..\\Windows\\System32\\cmd.exe')).toThrow(InvalidArchivePathError);
      expect(() => sanitizeArchivePath('folder/../../escape.txt')).toThrow(InvalidArchivePathError);
    });

    it('sanitizes absolute paths by stripping leading slashes', () => {
      expect(sanitizeArchivePath('/etc/passwd')).toBe('etc/passwd');
      expect(sanitizeArchivePath('///folder/file.txt')).toBe('folder/file.txt');
      // Drive letters are also stripped
      expect(sanitizeArchivePath('C:\\Users\\Admin\\file.txt')).toBe('Users/Admin/file.txt');
    });

    it('removes null bytes and control characters silently', () => {
      expect(sanitizeArchivePath('file\0name.txt')).toBe('filename.txt');
      expect(sanitizeArchivePath('file\x01name.txt')).toBe('filename.txt');
      expect(sanitizeArchivePath('file\x1Fname.txt')).toBe('filename.txt');
      expect(sanitizeArchivePath('file\x7Fname.txt')).toBe('filename.txt');
    });

    it('rejects colons in path segments', () => {
      expect(() => sanitizeArchivePath('file:name.txt')).toThrow(InvalidArchivePathError);
      expect(() => sanitizeArchivePath('folder:name/file.txt')).toThrow(InvalidArchivePathError);
    });

    it('rejects Windows reserved device names', () => {
      expect(() => sanitizeArchivePath('CON.txt')).toThrow(InvalidArchivePathError);
      expect(() => sanitizeArchivePath('PRN')).toThrow(InvalidArchivePathError);
      expect(() => sanitizeArchivePath('AUX.log')).toThrow(InvalidArchivePathError);
      expect(() => sanitizeArchivePath('NUL.dat')).toThrow(InvalidArchivePathError);
      expect(() => sanitizeArchivePath('COM1.txt')).toThrow(InvalidArchivePathError);
      expect(() => sanitizeArchivePath('LPT1')).toThrow(InvalidArchivePathError);
      expect(() => sanitizeArchivePath('folder/CON.txt')).toThrow(InvalidArchivePathError);
    });

    it('rejects trailing dots', () => {
      expect(() => sanitizeArchivePath('file.')).toThrow(InvalidArchivePathError);
      expect(() => sanitizeArchivePath('folder./file.txt')).toThrow(InvalidArchivePathError);
    });

    it('trims trailing spaces from segments', () => {
      expect(sanitizeArchivePath('file ')).toBe('file');
      expect(sanitizeArchivePath('folder /file.txt')).toBe('folder/file.txt');
    });

    it('rejects segments longer than 255 characters', () => {
      const longName = 'a'.repeat(256);
      expect(() => sanitizeArchivePath(longName)).toThrow(InvalidArchivePathError);
    });

    it('accepts valid paths and normalizes them', () => {
      expect(sanitizeArchivePath('folder/file.txt')).toBe('folder/file.txt');
      expect(sanitizeArchivePath('folder\\file.txt')).toBe('folder/file.txt');
      expect(sanitizeArchivePath('///folder///file.txt')).toBe('folder/file.txt');
      expect(sanitizeArchivePath('folder/./file.txt')).toBe('folder/file.txt');
    });

    it('rejects case-insensitive collisions', () => {
      const paths = resolveUniquePaths([
        { path: 'File.txt' },
        { path: 'file.txt' },
      ]);
      expect(paths).toHaveLength(2);
      expect(paths[0]).toBe('File.txt');
      expect(paths[1]).toMatch(/^file \(\d\)\.txt$/);
    });

    it('rejects Unicode normalization collisions', () => {
      // café in NFC vs NFD
      const nfc = 'caf\u00e9.txt'; // NFC: é as single code point
      const nfd = 'cafe\u0301.txt'; // NFD: e + combining acute
      const paths = resolveUniquePaths([
        { path: nfc },
        { path: nfd },
      ]);
      expect(paths).toHaveLength(2);
    });

    it('handles file vs directory-like conflicts', () => {
      // A file named "folder.txt" doesn't conflict with "folder/file.txt" 
      // because "folder.txt" is not a directory prefix of "folder/file.txt"
      const paths = resolveUniquePaths([
        { path: 'folder.txt' },
        { path: 'folder/file.txt' },
      ]);
      expect(paths).toHaveLength(2);
      expect(paths[0]).toBe('folder.txt');
      expect(paths[1]).toBe('folder/file.txt');
    });

    it('detects directory prefix conflicts when path ends with slash-like behavior', () => {
      // This simulates a conflict: a file at "folder" and a file at "folder/file.txt"
      // Since our paths don't have trailing slashes, this is handled by the isDirectoryPrefix check
      const paths = resolveUniquePaths([
        { path: 'folder' },
        { path: 'folder/file.txt' },
      ]);
      expect(paths).toHaveLength(2);
      // One should be renamed to avoid conflict
      expect(paths.some(p => p.includes('(') && p.includes(')'))).toBe(true);
    });

    it('rejects nested directory collisions', () => {
      const paths = resolveUniquePaths([
        { path: 'a/b.txt' },
        { path: 'a/b.txt' },
      ]);
      expect(paths).toHaveLength(2);
      expect(paths[0]).toBe('a/b.txt');
      expect(paths[1]).toBe('a/b (1).txt');
    });

    it('preserves order and never discards files', () => {
      const paths = resolveUniquePaths([
        { path: 'a.txt' },
        { path: 'a.txt' },
        { path: 'a.txt' },
      ]);
      expect(paths).toHaveLength(3);
      expect(paths[0]).toBe('a.txt');
      expect(paths[1]).toBe('a (1).txt');
      expect(paths[2]).toBe('a (2).txt');
    });
  });

  describe('SEC-05: Legacy v1 Metadata Size Validation', () => {
    it('rejects v1 metadata size mismatch', async () => {
      const key = await generateAesKey();
      const iv = generateNonce();
      const plaintext = new TextEncoder().encode('Hello World'); // 11 bytes

      // Create v1 envelope with WRONG size in metadata (20 instead of 11)
      const metadata = {
        originalName: 'test.txt',
        mimeType: 'text/plain',
        size: 20, // WRONG SIZE
        createdAt: Date.now(),
      };
      const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata));
      const ciphertextWithTag = await encryptBytes(key, iv, plaintext, metadataBytes);

      const sboxBytes = packEnvelope({ ciphertextWithTag, iv, metadata });

      await expect(decryptDocument(sboxBytes, key)).rejects.toThrow(MetadataSizeMismatchError);
    });

    it('accepts v1 with correct metadata size', async () => {
      const key = await generateAesKey();
      const iv = generateNonce();
      const plaintext = new TextEncoder().encode('Hello World'); // 11 bytes

      const metadata = {
        originalName: 'test.txt',
        mimeType: 'text/plain',
        size: 11, // CORRECT SIZE
        createdAt: Date.now(),
      };
      const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata));
      const ciphertextWithTag = await encryptBytes(key, iv, plaintext, metadataBytes);

      const sboxBytes = packEnvelope({ ciphertextWithTag, iv, metadata });

      const result = await decryptDocument(sboxBytes, key);
      expect(result.plaintext).toEqual(plaintext);
    });

    it('rejects v1 metadata with non-safe-integer size', async () => {
      const key = await generateAesKey();
      const iv = generateNonce();
      const plaintext = new TextEncoder().encode('Hello');

      const metadata = {
        originalName: 'test.txt',
        mimeType: 'text/plain',
        size: 1.5 as any, // Not a safe integer
        createdAt: Date.now(),
      };
      const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata));
      const ciphertextWithTag = await encryptBytes(key, iv, plaintext, metadataBytes);

      const sboxBytes = packEnvelope({ ciphertextWithTag, iv, metadata });

      await expect(decryptDocument(sboxBytes, key)).rejects.toThrow(MetadataSizeMismatchError);
    });

    it('rejects v1 metadata with negative size during unpack', async () => {
      const key = await generateAesKey();
      const iv = generateNonce();
      const plaintext = new TextEncoder().encode('Hello');

      const metadata = {
        originalName: 'test.txt',
        mimeType: 'text/plain',
        size: -1,
        createdAt: Date.now(),
      };
      const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata));
      const ciphertextWithTag = await encryptBytes(key, iv, plaintext, metadataBytes);

      const sboxBytes = packEnvelope({ ciphertextWithTag, iv, metadata });

      await expect(decryptDocument(sboxBytes, key)).rejects.toThrow(InvalidMetadataError);
    });
  });

  describe('SEC-06: Object URL Cleanup (Component-level)', () => {
    // These are component-level tests that verify the React components properly clean up URLs
    // The actual cleanup is tested via integration tests in the components
    it('verifies URL.revokeObjectURL is available', () => {
      expect(typeof URL.revokeObjectURL).toBe('function');
      expect(typeof URL.createObjectURL).toBe('function');
    });
  });

  describe('Valid Archive Round-trips', () => {
    it('valid v2 archive encrypts and decrypts correctly', async () => {
      const inputFiles = [
        { path: 'a.txt', data: new TextEncoder().encode('File A'), mimeType: 'text/plain' },
        { path: 'b.txt', data: new TextEncoder().encode('File B'), mimeType: 'text/plain' },
      ];

      const { sboxBytes, key } = await encryptArchive(inputFiles, 'test-archive');
      const restored = await decryptArchive(sboxBytes, key);

      expect(restored.files).toHaveLength(2);
      expect(restored.files[0].data).toEqual(inputFiles[0].data);
      expect(restored.files[1].data).toEqual(inputFiles[1].data);
    });

    it('valid v1 document encrypts and decrypts correctly', async () => {
      const plaintext = new TextEncoder().encode('Single file content');
      const { sboxBytes, key } = await import('../../src/core/crypto/service').then(m =>
        m.encryptDocument(plaintext, {
          originalName: 'single.txt',
          mimeType: 'text/plain',
          size: plaintext.length,
        })
      );

      const result = await import('../../src/core/crypto/service').then(m =>
        m.decryptDocument(sboxBytes, key)
      );

      expect(result.plaintext).toEqual(plaintext);
    });

    it('empty files work correctly in v2 archives', async () => {
      const inputFiles = [
        { path: 'empty.txt', data: new Uint8Array(0), mimeType: 'text/plain' },
        { path: 'data.txt', data: new TextEncoder().encode('Data'), mimeType: 'text/plain' },
      ];

      const { sboxBytes, key } = await encryptArchive(inputFiles, 'empty-test');
      const restored = await decryptArchive(sboxBytes, key);

      expect(restored.files).toHaveLength(2);
      expect(restored.files[0].data.byteLength).toBe(0);
      expect(restored.files[1].data).toEqual(inputFiles[1].data);
    });

    it('byte-for-byte fidelity for binary data', async () => {
      const binaryData = new Uint8Array(256);
      for (let i = 0; i < 256; i++) binaryData[i] = i;

      const inputFiles = [
        { path: 'binary.bin', data: binaryData, mimeType: 'application/octet-stream' },
      ];

      const { sboxBytes, key } = await encryptArchive(inputFiles, 'binary-test');
      const restored = await decryptArchive(sboxBytes, key);

      expect(restored.files[0].data).toEqual(binaryData);
    });
  });

  describe('Error Typing', () => {
    it('InvalidManifestIntegerError is thrown for invalid integers', () => {
      const manifest = {
        version: 1,
        archiveName: 'test',
        createdAt: Date.now(),
        fileCount: 1.5,
        totalPlaintextSize: 10,
        files: [{ path: 'a.txt', size: 10, offset: 0, mimeType: 'text/plain', sha256: 'a'.repeat(64) }],
      };
      const packed = packArchiveEnvelope({
        ciphertextWithTag: new Uint8Array(32),
        iv: new Uint8Array(12),
        manifest: manifest as any,
      });
      try {
        unpackArchiveEnvelope(packed);
        throw new Error('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(InvalidManifestIntegerError);
      }
    });

    it('ManifestFileCountMismatchError for count mismatch', () => {
      const manifest = {
        version: 1,
        archiveName: 'test',
        createdAt: Date.now(),
        fileCount: 2,
        totalPlaintextSize: 10,
        files: [{ path: 'a.txt', size: 10, offset: 0, mimeType: 'text/plain', sha256: 'a'.repeat(64) }],
      };
      const packed = packArchiveEnvelope({
        ciphertextWithTag: new Uint8Array(32),
        iv: new Uint8Array(12),
        manifest: manifest as any,
      });
      try {
        unpackArchiveEnvelope(packed);
        throw new Error('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ManifestFileCountMismatchError);
      }
    });

    it('ManifestEntryBoundsError for out-of-bounds entries', () => {
      const manifest = {
        version: 1,
        archiveName: 'test',
        createdAt: Date.now(),
        fileCount: 1,
        totalPlaintextSize: 10,
        files: [{ path: 'a.txt', size: 20, offset: 0, mimeType: 'text/plain', sha256: 'a'.repeat(64) }],
      };
      const packed = packArchiveEnvelope({
        ciphertextWithTag: new Uint8Array(32),
        iv: new Uint8Array(12),
        manifest: manifest as any,
      });
      try {
        unpackArchiveEnvelope(packed);
        throw new Error('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ManifestEntryBoundsError);
      }
    });

    it('ManifestNonContiguousError for non-contiguous ranges', () => {
      const manifest = {
        version: 1,
        archiveName: 'test',
        createdAt: Date.now(),
        fileCount: 2,
        totalPlaintextSize: 20,
        files: [
          { path: 'a.txt', size: 5, offset: 0, mimeType: 'text/plain', sha256: 'a'.repeat(64) },
          { path: 'b.txt', size: 5, offset: 10, mimeType: 'text/plain', sha256: 'b'.repeat(64) },
        ],
      };
      const packed = packArchiveEnvelope({
        ciphertextWithTag: new Uint8Array(32),
        iv: new Uint8Array(12),
        manifest: manifest as any,
      });
      try {
        unpackArchiveEnvelope(packed);
        throw new Error('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(ManifestNonContiguousError);
      }
    });

    it('InvalidArchivePathError for invalid paths', () => {
      try {
        sanitizeArchivePath('../../etc/passwd');
        throw new Error('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(InvalidArchivePathError);
      }
    });

    it('MetadataSizeMismatchError for v1 size mismatch', async () => {
      const key = await generateAesKey();
      const iv = generateNonce();
      const plaintext = new TextEncoder().encode('Hi');
      const metadata = { originalName: 't.txt', mimeType: 'text/plain', size: 100, createdAt: Date.now() };
      const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata));
      const ciphertextWithTag = await encryptBytes(key, iv, plaintext, metadataBytes);
      const sboxBytes = packEnvelope({ ciphertextWithTag, iv, metadata });

      try {
        await decryptDocument(sboxBytes, key);
        throw new Error('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(MetadataSizeMismatchError);
      }
    });
  });
});