import { describe, expect, it } from 'vitest';
import JSZip from 'jszip';
import { generateAesKey } from '../../src/core/crypto/aesGcm';
import { decryptAnyDocument, encryptDocument } from '../../src/core/crypto/service';
import { DecryptionError } from '../../src/core/crypto/types';
import { decryptArchive, encryptArchive } from '../../src/core/archive/archiveService';
import {
  EnvelopeTruncatedError,
  InvalidMagicBytesError,
} from '../../src/core/envelope/errors';
import { packEnvelope } from '../../src/core/envelope/pack';
import { encryptBytes, generateNonce } from '../../src/core/crypto/aesGcm';
import { computeSha256 } from '../../src/core/hashing/sha256';

describe('Verification of Four Required Test Cases', () => {
  // Case 1: Encrypt three files of different types, then decrypt and compare each recovered file.
  it('Case 1: Encrypts three files of different types, then decrypts and compares each recovered file', async () => {
    // 1. Text file (.txt / text/plain)
    const textContent = 'Confidential Report Header\nAuthor: Security Team\nDate: 2026-10-10';
    const textBytes = new TextEncoder().encode(textContent);

    // 2. Binary / Image simulation (.png / image/png with PNG magic bytes 0x89, 'P', 'N', 'G')
    const pngHeader = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    const pngBytes = new Uint8Array(2048);
    pngBytes.set(pngHeader, 0);
    for (let i = pngHeader.length; i < pngBytes.length; i++) {
      pngBytes[i] = (i * 7 + 13) % 256;
    }

    // 3. Document / PDF simulation (.pdf / application/pdf with %PDF-1.7 header)
    const pdfHeader = new TextEncoder().encode('%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n');
    const pdfBytes = new Uint8Array(4096);
    pdfBytes.set(pdfHeader, 0);
    for (let i = pdfHeader.length; i < pdfBytes.length; i++) {
      pdfBytes[i] = (i ^ 0xaa) % 256;
    }

    const inputFiles = [
      { path: 'report.txt', data: textBytes, mimeType: 'text/plain' },
      { path: 'avatar.png', data: pngBytes, mimeType: 'image/png' },
      { path: 'manual.pdf', data: pdfBytes, mimeType: 'application/pdf' },
    ];

    // Encrypt collection into .sbox archive
    const { sboxBytes, key, manifest } = await encryptArchive(inputFiles, 'case1-archive');
    expect(manifest.fileCount).toBe(3);

    // Decrypt archive
    const result = await decryptAnyDocument(sboxBytes, key);
    expect(result.type).toBe('archive');

    if (result.type === 'archive') {
      expect(result.files).toHaveLength(3);

      // Verify File 1: Text
      const recoveredText = result.files.find((f) => f.path === 'report.txt');
      expect(recoveredText).toBeDefined();
      expect(recoveredText!.data).toEqual(textBytes);
      expect(new TextDecoder().decode(recoveredText!.data)).toBe(textContent);
      expect(recoveredText!.mimeType).toBe('text/plain');
      expect(recoveredText!.sha256).toBe(await computeSha256(textBytes));

      // Verify File 2: PNG Binary
      const recoveredPng = result.files.find((f) => f.path === 'avatar.png');
      expect(recoveredPng).toBeDefined();
      expect(recoveredPng!.data).toEqual(pngBytes);
      expect(recoveredPng!.mimeType).toBe('image/png');
      expect(recoveredPng!.sha256).toBe(await computeSha256(pngBytes));

      // Verify File 3: PDF Document
      const recoveredPdf = result.files.find((f) => f.path === 'manual.pdf');
      expect(recoveredPdf).toBeDefined();
      expect(recoveredPdf!.data).toEqual(pdfBytes);
      expect(recoveredPdf!.mimeType).toBe('application/pdf');
      expect(recoveredPdf!.sha256).toBe(await computeSha256(pdfBytes));

      // Verify ZIP container extraction
      const zip = await JSZip.loadAsync(result.downloadBlob);
      const root = 'case1-archive/';
      expect(zip.file(`${root}report.txt`)).not.toBeNull();
      expect(zip.file(`${root}avatar.png`)).not.toBeNull();
      expect(zip.file(`${root}manual.pdf`)).not.toBeNull();

      const zipText = await zip.file(`${root}report.txt`)!.async('uint8array');
      const zipPng = await zip.file(`${root}avatar.png`)!.async('uint8array');
      const zipPdf = await zip.file(`${root}manual.pdf`)!.async('uint8array');

      expect(zipText).toEqual(textBytes);
      expect(zipPng).toEqual(pngBytes);
      expect(zipPdf).toEqual(pdfBytes);
    }
  });

  // Case 2: Encrypt a nested folder containing duplicate filenames and an empty file.
  it('Case 2: Encrypts a nested folder containing duplicate filenames and an empty file', async () => {
    const summaryRoot = new TextEncoder().encode('Summary at root folder');
    const summaryDocs = new TextEncoder().encode('Summary inside docs folder');
    const note1 = new TextEncoder().encode('First copy of note');
    const note2 = new TextEncoder().encode('Second duplicate copy of note in same folder');
    const emptyFile = new Uint8Array(0); // 0-byte file

    const inputFiles = [
      { path: 'project/summary.txt', data: summaryRoot, mimeType: 'text/plain' },
      { path: 'project/docs/summary.txt', data: summaryDocs, mimeType: 'text/plain' },
      { path: 'project/notes.txt', data: note1, mimeType: 'text/plain' },
      { path: 'project/notes.txt', data: note2, mimeType: 'text/plain' }, // Duplicate in same path!
      { path: 'project/data/empty.bin', data: emptyFile, mimeType: 'application/octet-stream' },
    ];

    const { sboxBytes, key, manifest } = await encryptArchive(inputFiles, 'case2-nested');
    expect(manifest.fileCount).toBe(5);

    const result = await decryptAnyDocument(sboxBytes, key);
    expect(result.type).toBe('archive');

    if (result.type === 'archive') {
      expect(result.files).toHaveLength(5);

      // Verify path preservation for nested paths with same filename
      const rootSummary = result.files.find((f) => f.path === 'project/summary.txt');
      const docsSummary = result.files.find((f) => f.path === 'project/docs/summary.txt');
      expect(rootSummary).toBeDefined();
      expect(docsSummary).toBeDefined();
      expect(rootSummary!.data).toEqual(summaryRoot);
      expect(docsSummary!.data).toEqual(summaryDocs);

      // Verify safe deduplication for collision in the exact same directory
      const originalNote = result.files.find((f) => f.path === 'project/notes.txt');
      const deduplicatedNote = result.files.find((f) => f.path === 'project/notes (1).txt');
      expect(originalNote).toBeDefined();
      expect(deduplicatedNote).toBeDefined();
      expect(originalNote!.data).toEqual(note1);
      expect(deduplicatedNote!.data).toEqual(note2);

      // Verify empty file
      const emptyRecovered = result.files.find((f) => f.path === 'project/data/empty.bin');
      expect(emptyRecovered).toBeDefined();
      expect(emptyRecovered!.data.byteLength).toBe(0);
      expect(emptyRecovered!.data).toEqual(emptyFile);

      // Verify ZIP container preserves directory hierarchy
      const zip = await JSZip.loadAsync(result.downloadBlob);
      const root = 'case2-nested/';
      expect(zip.file(`${root}project/summary.txt`)).not.toBeNull();
      expect(zip.file(`${root}project/docs/summary.txt`)).not.toBeNull();
      expect(zip.file(`${root}project/notes.txt`)).not.toBeNull();
      expect(zip.file(`${root}project/notes (1).txt`)).not.toBeNull();
      expect(zip.file(`${root}project/data/empty.bin`)).not.toBeNull();
    }
  });

  // Case 3: Try the wrong key and modify the encrypted archive; both must fail safely.
  it('Case 3: Wrong key and modified encrypted archive both fail safely', async () => {
    const file1 = new TextEncoder().encode('Sensitive confidential archive contents');
    const file2 = new TextEncoder().encode('Financial ledger 2026');

    const inputFiles = [
      { path: 'doc1.txt', data: file1 },
      { path: 'doc2.txt', data: file2 },
    ];

    const { sboxBytes, key } = await encryptArchive(inputFiles, 'case3-test');

    // Subcase 3A: Attempt decryption with wrong key
    const wrongKey = await generateAesKey();
    await expect(decryptArchive(sboxBytes, wrongKey)).rejects.toThrow(DecryptionError);
    await expect(decryptAnyDocument(sboxBytes, wrongKey)).rejects.toThrow(DecryptionError);

    // Subcase 3B: Modify ciphertext payload bytes
    const tamperedCiphertext = new Uint8Array(sboxBytes);
    // Flip bits in ciphertext area (near the end, but before tag)
    tamperedCiphertext[tamperedCiphertext.length - 20] ^= 0x5a;
    await expect(decryptArchive(tamperedCiphertext, key)).rejects.toThrow(DecryptionError);

    // Subcase 3C: Modify 16-byte authentication tag
    const tamperedTag = new Uint8Array(sboxBytes);
    tamperedTag[tamperedTag.length - 1] ^= 0x01;
    await expect(decryptArchive(tamperedTag, key)).rejects.toThrow(DecryptionError);

    // Subcase 3D: Modify manifest header (AAD tampering)
    const tamperedHeader = new Uint8Array(sboxBytes);
    // Mutate the word "doc1" inside the manifest JSON portion
    for (let i = 23; i < 200; i++) {
      if (
        tamperedHeader[i] === 0x64 && // 'd'
        tamperedHeader[i + 1] === 0x6f && // 'o'
        tamperedHeader[i + 2] === 0x63 // 'c'
      ) {
        tamperedHeader[i] = 0x78; // 'x' -> "xoc"
        break;
      }
    }
    await expect(decryptArchive(tamperedHeader, key)).rejects.toThrow(DecryptionError);

    // Subcase 3E: Truncated archive payload (cut off in ciphertext/tag)
    const truncatedPayload = sboxBytes.subarray(0, sboxBytes.length - 30);
    await expect(decryptArchive(truncatedPayload, key)).rejects.toThrow(DecryptionError);

    // Subcase 3F: Truncated archive header (smaller than minimum envelope size)
    const truncatedHeader = sboxBytes.subarray(0, 20);
    await expect(decryptArchive(truncatedHeader, key)).rejects.toThrow(EnvelopeTruncatedError);

    // Subcase 3G: Corrupted magic bytes
    const corruptedMagic = new Uint8Array(sboxBytes);
    corruptedMagic[0] = 0x00;
    await expect(decryptArchive(corruptedMagic, key)).rejects.toThrow(InvalidMagicBytesError);
  });

  // Case 4: Decrypt a single-file v1 archive created before the multi-file update.
  it('Case 4: Decrypts a single-file v1 archive created before the multi-file update', async () => {
    // Construct a pure Version 1 single-file .sbox container as created prior to the update:
    // Header format: [Magic: "SBOX"] [Ver: 0x01] [Algo: 0x01] [IVLen: 12] [IV: 12B] [MetaLen: uint16] [Meta: JSON] [Ciphertext+Tag]
    const originalFilename = 'legacy_v1_contract.pdf';
    const originalMime = 'application/pdf';
    const originalPlaintext = new TextEncoder().encode(
      '%PDF-1.4 Legacy Document encrypted with SecureBox v1 engine before archive features were introduced.'
    );

    // Create using v1 single-file encryptDocument
    const { sboxBytes: v1SboxBytes, key: v1Key, metadata: v1Metadata } = await encryptDocument(
      originalPlaintext,
      {
        originalName: originalFilename,
        mimeType: originalMime,
        size: originalPlaintext.length,
      }
    );
    expect(v1Metadata.originalName).toBe(originalFilename);

    // Verify raw envelope header is strictly Version 1
    expect(v1SboxBytes[0]).toBe(0x53); // 'S'
    expect(v1SboxBytes[1]).toBe(0x42); // 'B'
    expect(v1SboxBytes[2]).toBe(0x4f); // 'O'
    expect(v1SboxBytes[3]).toBe(0x58); // 'X'
    expect(v1SboxBytes[4]).toBe(0x01); // Version 1 strictly!

    // Also manually construct a v1 container directly from primitives to simulate an archive saved months ago
    const manualKey = await generateAesKey();
    const manualIv = generateNonce();
    const manualMeta = {
      originalName: 'tax_return_2024.pdf',
      mimeType: 'application/pdf',
      size: originalPlaintext.length,
      createdAt: 1700000000000,
    };
    const manualMetaBytes = new TextEncoder().encode(JSON.stringify(manualMeta));
    const manualCiphertext = await encryptBytes(manualKey, manualIv, originalPlaintext, manualMetaBytes);
    const manualV1Sbox = packEnvelope({
      ciphertextWithTag: manualCiphertext,
      iv: manualIv,
      metadata: manualMeta,
    });
    expect(manualV1Sbox[4]).toBe(0x01); // Version 1

    // 1. Decrypt through decryptAnyDocument (the router used by DecryptPanel)
    const resultFromService = await decryptAnyDocument(v1SboxBytes, v1Key);
    expect(resultFromService.type).toBe('single');

    if (resultFromService.type === 'single') {
      expect(resultFromService.metadata.originalName).toBe(originalFilename);
      expect(resultFromService.metadata.mimeType).toBe(originalMime);
      expect(resultFromService.downloadFilename).toBe(originalFilename);
      expect(resultFromService.plaintext).toEqual(originalPlaintext);
      expect(new TextDecoder().decode(resultFromService.plaintext)).toBe(
        new TextDecoder().decode(originalPlaintext)
      );
    }

    // 2. Decrypt the manually constructed legacy v1 container through decryptAnyDocument
    const resultFromManual = await decryptAnyDocument(manualV1Sbox, manualKey);
    expect(resultFromManual.type).toBe('single');

    if (resultFromManual.type === 'single') {
      expect(resultFromManual.metadata.originalName).toBe('tax_return_2024.pdf');
      expect(resultFromManual.metadata.mimeType).toBe('application/pdf');
      expect(resultFromManual.downloadFilename).toBe('tax_return_2024.pdf');
      expect(resultFromManual.plaintext).toEqual(originalPlaintext);
    }
  });
});
