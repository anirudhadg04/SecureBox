import { decryptBytes, encryptBytes, generateAesKey, generateNonce } from '../crypto/aesGcm';
import { computeSha256 } from '../hashing/sha256';
import { packArchiveEnvelope, unpackArchiveEnvelope } from '../envelope/archiveEnvelope';
import { ArchiveIntegrityMismatchError } from '../envelope/errors';
import {
  ArchiveFileEntry,
  ArchiveManifest,
  InputArchiveFile,
  RestoredArchive,
  RestoredArchiveFile,
  resolveUniquePaths,
  restoreArchivePath,
} from './types';
import { createRestoredZipBlob } from './zipRestore';

export interface EncryptArchiveResult {
  /** The packed .sbox v2 archive file bytes */
  sboxBytes: Uint8Array;
  /** The 256-bit AES-GCM CryptoKey */
  key: CryptoKey;
  /** The authenticated archive manifest */
  manifest: ArchiveManifest;
}

/**
 * Encrypts multiple files into a single, authenticated .sbox collection archive.
 *
 * All files are packaged directly into the encrypted container with a cryptographically
 * bound manifest (authenticated via AES-256-GCM AAD). No unencrypted ZIP is created.
 *
 * @param inputFiles Array of files with relative paths and binary contents.
 * @param archiveName Name for the collection (defaults to "securebox-archive").
 * @param existingKey Optional pre-existing CryptoKey.
 */
export async function encryptArchive(
  inputFiles: InputArchiveFile[],
  archiveName: string = 'securebox-archive',
  existingKey?: CryptoKey
): Promise<EncryptArchiveResult> {
  if (inputFiles.length === 0) {
    throw new Error('Cannot create an archive with zero files');
  }

  // 1. Resolve unique, sanitized relative paths
  const uniquePaths = resolveUniquePaths(inputFiles);

  // 2. Compute individual file hashes and construct manifest entries
  const manifestFiles: ArchiveFileEntry[] = [];
  let currentOffset = 0;

  for (let i = 0; i < inputFiles.length; i++) {
    const file = inputFiles[i];
    const path = uniquePaths[i];
    const sha256 = await computeSha256(file.data);

    manifestFiles.push({
      path,
      size: file.data.byteLength,
      offset: currentOffset,
      mimeType: file.mimeType || 'application/octet-stream',
      sha256,
    });

    currentOffset += file.data.byteLength;
  }

  const totalPlaintextSize = currentOffset;

  // 3. Assemble the unencrypted payload buffer in memory
  const payloadBuffer = new Uint8Array(totalPlaintextSize);
  for (let i = 0; i < inputFiles.length; i++) {
    const file = inputFiles[i];
    const entry = manifestFiles[i];
    payloadBuffer.set(file.data, entry.offset);
  }

  // 4. Construct manifest object
  const manifest: ArchiveManifest = {
    version: 1,
    archiveName: archiveName.replace(/\.sbox$/i, ''),
    createdAt: Date.now(),
    fileCount: manifestFiles.length,
    totalPlaintextSize,
    files: manifestFiles,
  };

  const manifestJson = JSON.stringify(manifest);
  const manifestBytes = new TextEncoder().encode(manifestJson);

  // 5. Generate fresh key and 96-bit nonce
  const key = existingKey ?? (await generateAesKey());
  const nonce = generateNonce();

  // 6. Authenticated encryption (manifest is bound as AAD)
  const ciphertextWithTag = await encryptBytes(
    key,
    nonce,
    payloadBuffer,
    manifestBytes
  );

  // 7. Package into .sbox v2 container
  const sboxBytes = packArchiveEnvelope({
    ciphertextWithTag,
    iv: nonce,
    manifest,
  });

  return {
    sboxBytes,
    key,
    manifest,
  };
}

/**
 * Decrypts, validates, and unpacks a .sbox collection archive.
 *
 * Verifies envelope format, authenticates AES-256-GCM ciphertext + manifest AAD,
 * validates file bounds and individual SHA-256 digests, and generates a clean ZIP
 * that extracts into a single recovered folder.
 *
 * @param sboxBytes Raw binary content of the .sbox file.
 * @param key The 256-bit CryptoKey.
 * @returns Restored archive with individual file contents and downloadable ZIP.
 */
export async function decryptArchive(
  sboxBytes: Uint8Array,
  key: CryptoKey
): Promise<RestoredArchive> {
  // 1. Unpack archive envelope and validate header/manifest structure
  const { iv, manifest, manifestBytes, ciphertextWithTag } = unpackArchiveEnvelope(sboxBytes);

  // 2. Authenticated decryption (rejects immediately if key is wrong or any byte is tampered)
  const plaintext = await decryptBytes(key, iv, ciphertextWithTag, manifestBytes);

  // 3. Verify total recovered plaintext length
  if (plaintext.byteLength !== manifest.totalPlaintextSize) {
    throw new ArchiveIntegrityMismatchError(
      `Recovered payload size (${plaintext.byteLength} B) does not match manifest size (${manifest.totalPlaintextSize} B)`
    );
  }

  // 4. Extract individual files and verify per-file SHA-256 digests
  const restoredFiles: RestoredArchiveFile[] = [];

  for (const entry of manifest.files) {
    if (entry.offset + entry.size > plaintext.byteLength) {
      throw new ArchiveIntegrityMismatchError(
        `Entry ${entry.path} extends beyond decrypted buffer bounds`
      );
    }

    const fileData = plaintext.slice(entry.offset, entry.offset + entry.size);
    const computedHash = await computeSha256(fileData);

    if (computedHash !== entry.sha256) {
      throw new ArchiveIntegrityMismatchError(
        `SHA-256 checksum mismatch for "${entry.path}". Expected ${entry.sha256}, got ${computedHash}`
      );
    }

    const cleanPath = restoreArchivePath(entry.path);

    restoredFiles.push({
      path: cleanPath,
      originalPath: entry.path,
      data: fileData,
      mimeType: entry.mimeType,
      sha256: computedHash,
    });
  }

  // 5. Ensure paths in restored collection are unique (defense-in-depth against duplicate entries).
  //    Uses the restore-time sanitizer so defensive renames never reject an authenticated archive.
  const uniquePaths = resolveUniquePaths(restoredFiles.map((f) => ({ path: f.path })), restoreArchivePath);
  for (let i = 0; i < restoredFiles.length; i++) {
    restoredFiles[i].path = uniquePaths[i];
  }

  // 6. Generate downloadable ZIP file extracting into a root folder
  const zipBlob = await createRestoredZipBlob(restoredFiles, manifest.archiveName);

  return {
    manifest,
    files: restoredFiles,
    zipBlob,
    zipFilename: `${manifest.archiveName || 'securebox-archive'}.zip`,
  };
}
