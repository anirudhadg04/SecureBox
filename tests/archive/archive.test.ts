import { describe, expect, it } from 'vitest';
import JSZip from 'jszip';
import { generateAesKey } from '../../src/core/crypto/aesGcm';
import { decryptAnyDocument, encryptDocument } from '../../src/core/crypto/service';
import { DecryptionError } from '../../src/core/crypto/types';
import { decryptArchive, encryptArchive } from '../../src/core/archive/archiveService';
import {
  ArchiveIntegrityMismatchError,
  EnvelopeTruncatedError,
  InvalidArchiveManifestError,
  InvalidMagicBytesError,
  UnsupportedVersionError,
} from '../../src/core/envelope/errors';
import {
  detectEnvelopeVersion,
  packArchiveEnvelope,
  unpackArchiveEnvelope,
} from '../../src/core/envelope/archiveEnvelope';
import { resolveUniquePaths, sanitizeArchivePath } from '../../src/core/archive/types';

describe('Multi-File Archive Encryption & Folder Restoration Engine', () => {
  it('encrypts and decrypts multiple files with exact byte-for-byte fidelity', async () => {
    const file1Data = new TextEncoder().encode('Invoice #1001 for Acme Corp');
    const file2Data = new Uint8Array([0x00, 0xff, 0x42, 0x13, 0x37]);
    const file3Data = new TextEncoder().encode('ReadMe instructions in text');

    const inputFiles = [
      { path: 'invoice.txt', data: file1Data, mimeType: 'text/plain' },
      { path: 'binary.dat', data: file2Data, mimeType: 'application/octet-stream' },
      { path: 'readme.txt', data: file3Data, mimeType: 'text/plain' },
    ];

    const { sboxBytes, key, manifest } = await encryptArchive(inputFiles, 'project-files');

    expect(manifest.fileCount).toBe(3);
    expect(manifest.totalPlaintextSize).toBe(file1Data.length + file2Data.length + file3Data.length);
    expect(detectEnvelopeVersion(sboxBytes)).toBe(2);

    // Decrypt archive
    const restored = await decryptArchive(sboxBytes, key);

    expect(restored.manifest.fileCount).toBe(3);
    expect(restored.files).toHaveLength(3);

    // Verify exact bytes
    expect(restored.files[0].path).toBe('invoice.txt');
    expect(restored.files[0].data).toEqual(file1Data);

    expect(restored.files[1].path).toBe('binary.dat');
    expect(restored.files[1].data).toEqual(file2Data);

    expect(restored.files[2].path).toBe('readme.txt');
    expect(restored.files[2].data).toEqual(file3Data);

    // Verify ZIP contains a root folder with the files
    const zip = await JSZip.loadAsync(restored.zipBlob);
    const rootFolder = 'project-files/';
    expect(zip.folder('project-files')).not.toBeNull();
    const invoiceFileInZip = zip.file(`${rootFolder}invoice.txt`);
    expect(invoiceFileInZip).not.toBeNull();
    const invoiceText = await invoiceFileInZip!.async('text');
    expect(invoiceText).toBe('Invoice #1001 for Acme Corp');
  });

  it('correctly supports empty (0-byte) files in multi-file archives', async () => {
    const emptyFile = new Uint8Array(0);
    const regularFile = new TextEncoder().encode('Non-empty content');

    const inputFiles = [
      { path: 'empty.txt', data: emptyFile, mimeType: 'text/plain' },
      { path: 'regular.txt', data: regularFile, mimeType: 'text/plain' },
    ];

    const { sboxBytes, key } = await encryptArchive(inputFiles, 'test-empty');
    const restored = await decryptArchive(sboxBytes, key);

    expect(restored.files[0].path).toBe('empty.txt');
    expect(restored.files[0].data.byteLength).toBe(0);

    expect(restored.files[1].path).toBe('regular.txt');
    expect(restored.files[1].data).toEqual(regularFile);
  });

  it('preserves nested subdirectories and restores folder hierarchies', async () => {
    const doc1 = new TextEncoder().encode('Subfolder document 1');
    const doc2 = new TextEncoder().encode('Subfolder document 2');

    const inputFiles = [
      { path: 'financials/2026/q1.txt', data: doc1, mimeType: 'text/plain' },
      { path: 'financials/2026/q2.txt', data: doc2, mimeType: 'text/plain' },
    ];

    const { sboxBytes, key } = await encryptArchive(inputFiles, 'company-reports');
    const restored = await decryptArchive(sboxBytes, key);

    expect(restored.files[0].path).toBe('financials/2026/q1.txt');
    expect(restored.files[1].path).toBe('financials/2026/q2.txt');

    // Verify ZIP contains the full hierarchy
    const zip = await JSZip.loadAsync(restored.zipBlob);
    expect(zip.file('company-reports/financials/2026/q1.txt')).not.toBeNull();
    expect(zip.file('company-reports/financials/2026/q2.txt')).not.toBeNull();
  });

  it('sanitizes directory traversal attempts (.. and drive letters)', () => {
    expect(sanitizeArchivePath('../../etc/passwd')).toBe('etc/passwd');
    expect(sanitizeArchivePath('..\\..\\Windows\\System32\\cmd.exe')).toBe('Windows/System32/cmd.exe');
    expect(sanitizeArchivePath('C:\\Users\\Admin\\Secret.doc')).toBe('Users/Admin/Secret.doc');
    expect(sanitizeArchivePath('///nested/path/file.txt')).toBe('nested/path/file.txt');
    expect(sanitizeArchivePath('../../../')).toBe('unnamed-file');
  });

  it('safely handles duplicate filenames without silent overwrites', async () => {
    const file1 = new TextEncoder().encode('First copy of report');
    const file2 = new TextEncoder().encode('Second copy of report');
    const file3 = new TextEncoder().encode('Third copy of report');

    const inputFiles = [
      { path: 'report.pdf', data: file1 },
      { path: 'report.pdf', data: file2 },
      { path: 'report.pdf', data: file3 },
    ];

    const uniquePaths = resolveUniquePaths(inputFiles);
    expect(uniquePaths).toEqual(['report.pdf', 'report (1).pdf', 'report (2).pdf']);

    const { sboxBytes, key } = await encryptArchive(inputFiles, 'duplicate-test');
    const restored = await decryptArchive(sboxBytes, key);

    expect(restored.files[0].path).toBe('report.pdf');
    expect(restored.files[0].data).toEqual(file1);

    expect(restored.files[1].path).toBe('report (1).pdf');
    expect(restored.files[1].data).toEqual(file2);

    expect(restored.files[2].path).toBe('report (2).pdf');
    expect(restored.files[2].data).toEqual(file3);
  });

  it('rejects decryption when an incorrect key is supplied', async () => {
    const inputFiles = [{ path: 'secret.txt', data: new TextEncoder().encode('Confidential') }];
    const { sboxBytes } = await encryptArchive(inputFiles);

    const wrongKey = await generateAesKey();
    await expect(decryptArchive(sboxBytes, wrongKey)).rejects.toThrow(DecryptionError);
  });

  it('rejects decryption when ciphertext payload is corrupted', async () => {
    const inputFiles = [
      { path: 'doc1.txt', data: new TextEncoder().encode('Doc 1') },
      { path: 'doc2.txt', data: new TextEncoder().encode('Doc 2') },
    ];

    const { sboxBytes, key } = await encryptArchive(inputFiles);

    // Corrupt one byte of ciphertext
    const corrupted = new Uint8Array(sboxBytes);
    corrupted[corrupted.length - 8] ^= 0xff;

    await expect(decryptArchive(corrupted, key)).rejects.toThrow(DecryptionError);
  });

  it('rejects decryption when manifest metadata is tampered with (AAD binding protection)', async () => {
    const inputFiles = [{ path: 'salary_data.csv', data: new TextEncoder().encode('Alice,100') }];
    const { sboxBytes, key } = await encryptArchive(inputFiles);

    // Find "salary" in the manifest portion and mutate one character
    const tampered = new Uint8Array(sboxBytes);
    let mutated = false;
    for (let i = 0; i < tampered.length - 6; i++) {
      if (
        tampered[i] === 0x73 && // 's'
        tampered[i + 1] === 0x61 && // 'a'
        tampered[i + 2] === 0x6c && // 'l'
        tampered[i + 3] === 0x61 && // 'a'
        tampered[i + 4] === 0x72 && // 'r'
        tampered[i + 5] === 0x79 // 'y'
      ) {
        tampered[i] = 0x78; // 'xalary'
        mutated = true;
        break;
      }
    }
    expect(mutated).toBe(true);

    // Decryption must reject because manifest is bound via AES-GCM AAD
    await expect(decryptArchive(tampered, key)).rejects.toThrow(DecryptionError);
  });

  it('rejects truncated archive envelopes', async () => {
    const inputFiles = [{ path: 'test.txt', data: new TextEncoder().encode('Hello') }];
    const { sboxBytes } = await encryptArchive(inputFiles);

    const truncated = sboxBytes.subarray(0, sboxBytes.length - 20);
    expect(() => unpackArchiveEnvelope(truncated)).toThrow(EnvelopeTruncatedError);
  });

  it('detectEnvelopeVersion distinguishes between single-file (v1) and archive (v2)', async () => {
    // Single file v1
    const single = await encryptDocument(new TextEncoder().encode('Single file'), {
      originalName: 'single.txt',
      mimeType: 'text/plain',
      size: 11,
    });
    expect(detectEnvelopeVersion(single.sboxBytes)).toBe(1);

    // Archive v2
    const archive = await encryptArchive([
      { path: 'a.txt', data: new TextEncoder().encode('A') },
      { path: 'b.txt', data: new TextEncoder().encode('B') },
    ]);
    expect(detectEnvelopeVersion(archive.sboxBytes)).toBe(2);
  });

  it('decryptAnyDocument seamlessly handles both single-file (v1) and archive (v2)', async () => {
    // 1. Single file test through decryptAnyDocument
    const singleData = new TextEncoder().encode('Single file payload');
    const { sboxBytes: singleSbox, key: singleKey } = await encryptDocument(singleData, {
      originalName: 'single.pdf',
      mimeType: 'application/pdf',
      size: singleData.length,
    });

    const singleResult = await decryptAnyDocument(singleSbox, singleKey);
    expect(singleResult.type).toBe('single');
    if (singleResult.type === 'single') {
      expect(singleResult.plaintext).toEqual(singleData);
      expect(singleResult.downloadFilename).toBe('single.pdf');
    }

    // 2. Archive test through decryptAnyDocument
    const { sboxBytes: archiveSbox, key: archiveKey } = await encryptArchive([
      { path: 'first.txt', data: new TextEncoder().encode('First') },
      { path: 'second.txt', data: new TextEncoder().encode('Second') },
    ], 'unified-test');

    const archiveResult = await decryptAnyDocument(archiveSbox, archiveKey);
    expect(archiveResult.type).toBe('archive');
    if (archiveResult.type === 'archive') {
      expect(archiveResult.files).toHaveLength(2);
      expect(archiveResult.downloadFilename).toBe('unified-test.zip');
    }
  });

  it('rejects envelopes with corrupted manifest length or invalid manifest JSON', () => {
    const invalidHeader = new Uint8Array(50);
    invalidHeader.set([0x53, 0x42, 0x4f, 0x58], 0); // "SBOX"
    invalidHeader[4] = 0x02; // Version 2
    invalidHeader[5] = 0x01; // AES-GCM
    invalidHeader[6] = 12; // Nonce length
    // IV (bytes 7..18)
    const dv = new DataView(invalidHeader.buffer);
    dv.setUint32(19, 10, false); // Manifest length 10
    // Fill bytes 23..32 with invalid JSON
    invalidHeader.set(new TextEncoder().encode('not-json!!'), 23);

    expect(() => unpackArchiveEnvelope(invalidHeader)).toThrow(InvalidArchiveManifestError);
  });

  it('rejects archive envelopes with invalid magic bytes or unsupported versions', () => {
    const badMagic = new Uint8Array(60);
    badMagic.set([0x41, 0x42, 0x43, 0x44], 0); // "ABCD"
    expect(() => unpackArchiveEnvelope(badMagic)).toThrow(InvalidMagicBytesError);

    const badVersion = new Uint8Array(60);
    badVersion.set([0x53, 0x42, 0x4f, 0x58], 0); // "SBOX"
    badVersion[4] = 0x03; // Version 3
    expect(() => unpackArchiveEnvelope(badVersion)).toThrow(UnsupportedVersionError);
  });

  it('rejects archive envelopes where entry bounds exceed total declared plain text size', () => {
    const manifestJson = JSON.stringify({
      version: 1,
      archiveName: 'overflow',
      createdAt: 1,
      fileCount: 1,
      totalPlaintextSize: 10,
      files: [
        {
          path: 'overflow.txt',
          size: 20, // size 20 exceeds totalPlaintextSize 10!
          offset: 0,
          mimeType: 'text/plain',
          sha256: 'a'.repeat(64),
        },
      ],
    });
    const packed = packArchiveEnvelope({
      ciphertextWithTag: new Uint8Array(32),
      iv: new Uint8Array(12),
      manifest: JSON.parse(manifestJson),
    });

    expect(() => unpackArchiveEnvelope(packed)).toThrow(ArchiveIntegrityMismatchError);
  });
});
