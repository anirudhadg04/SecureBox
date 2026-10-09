/**
 * Types and interfaces for SecureBox multi-file archives.
 */

export interface ArchiveFileEntry {
  /** Relative file path within the archive (e.g. "docs/invoice.pdf") */
  path: string;
  /** Size in bytes of unencrypted file */
  size: number;
  /** Byte offset in the concatenated unencrypted payload */
  offset: number;
  /** MIME type of the file */
  mimeType: string;
  /** SHA-256 hex digest of the file's unencrypted contents */
  sha256: string;
}

export interface ArchiveManifest {
  version: 1;
  archiveName: string;
  createdAt: number;
  fileCount: number;
  totalPlaintextSize: number;
  files: ArchiveFileEntry[];
}

export interface InputArchiveFile {
  /** Relative path or filename */
  path: string;
  /** Raw file bytes */
  data: Uint8Array;
  /** MIME type if known */
  mimeType?: string;
}

export interface RestoredArchiveFile {
  /** Sanitized, unique relative path */
  path: string;
  /** Original declared path before deduplication */
  originalPath: string;
  /** Unencrypted file contents */
  data: Uint8Array;
  /** MIME type */
  mimeType: string;
  /** Verified SHA-256 digest */
  sha256: string;
}

export interface RestoredArchive {
  manifest: ArchiveManifest;
  files: RestoredArchiveFile[];
  /** Downloadable ZIP containing all restored files in a folder */
  zipBlob: Blob;
  /** Suggested download filename for the ZIP */
  zipFilename: string;
}

/**
 * Sanitizes a file path to prevent directory traversal attacks and invalid characters.
 * Replaces backslashes, strips leading/trailing slashes, removes '..' segments,
 * and eliminates drive letters.
 */
export function sanitizeArchivePath(rawPath: string): string {
  // Replace backslashes with forward slashes
  let sanitized = rawPath.replace(/\\/g, '/');

  // Strip drive letters like "C:"
  sanitized = sanitized.replace(/^[a-zA-Z]:/, '');

  // Strip leading slashes
  sanitized = sanitized.replace(/^\/+/, '');

  // Split into path segments and filter out empty segments or traversal
  const segments = sanitized.split('/').filter((seg) => {
    const trimmed = seg.trim();
    return trimmed.length > 0 && trimmed !== '.' && trimmed !== '..';
  });

  if (segments.length === 0) {
    return 'unnamed-file';
  }

  // Re-join with single forward slash
  return segments.join('/');
}

/**
 * Ensures all paths in an archive are unique to prevent silent overwriting.
 * Appends " (1)", " (2)", etc. before the extension if duplicates occur.
 */
export function resolveUniquePaths(entries: { path: string }[]): string[] {
  const seenPaths = new Set<string>();
  const resolved: string[] = [];

  for (const entry of entries) {
    const cleanPath = sanitizeArchivePath(entry.path);

    if (!seenPaths.has(cleanPath)) {
      seenPaths.add(cleanPath);
      resolved.push(cleanPath);
      continue;
    }

    // Duplicate found: split directory, basename, and extension
    const lastSlash = cleanPath.lastIndexOf('/');
    const dir = lastSlash !== -1 ? cleanPath.substring(0, lastSlash + 1) : '';
    const filename = lastSlash !== -1 ? cleanPath.substring(lastSlash + 1) : cleanPath;

    const lastDot = filename.lastIndexOf('.');
    const baseName = lastDot !== -1 ? filename.substring(0, lastDot) : filename;
    const extension = lastDot !== -1 ? filename.substring(lastDot) : '';

    let counter = 1;
    let candidate = `${dir}${baseName} (${counter})${extension}`;
    while (seenPaths.has(candidate)) {
      counter++;
      candidate = `${dir}${baseName} (${counter})${extension}`;
    }

    seenPaths.add(candidate);
    resolved.push(candidate);
  }

  return resolved;
}
