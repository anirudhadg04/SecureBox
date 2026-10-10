import { InvalidArchivePathError } from '../envelope/errors';

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
 * Windows reserved device names that cannot be used as filenames.
 * Source: https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file
 */
const WINDOWS_RESERVED_NAMES = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
  'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
]);

/**
 * Checks if a path segment is a Windows reserved device name (with or without extension).
 */
function isWindowsReservedName(segment: string): boolean {
  const upper = segment.toUpperCase();
  // Check base name without extension
  const baseName = upper.split('.')[0];
  return WINDOWS_RESERVED_NAMES.has(baseName);
}

/**
 * Characters that must never appear in an archive path: C0 controls, DEL, C1
 * controls, and Unicode format characters (bidi overrides, zero-width and
 * BOM code points). The `u` flag enables the \p{Cf} property escape.
 */
const UNSAFE_PATH_CHARS = /[\u0000-\u001F\u007f-\u009f\p{Cf}]/gu;

/**
 * Normalizes a path segment for cross-platform comparison.
 * - Applies Unicode NFC normalization
 * - Applies a full case fold (toLowerCase -> toUpperCase -> toLowerCase) so that
 *   folding matches the NTFS upcase table, which maps U+0131 to "I" and U+017F
 *   to "S"; plain toLowerCase() leaves those distinct.
 * - Removes trailing dots and spaces (Windows behavior)
 */
function normalizePathSegment(segment: string): string {
  return segment
    .normalize('NFC')
    .toLowerCase()
    .toUpperCase()
    .toLowerCase()
    .replace(/[.\s]+$/, '');
}

/**
 * Validates and sanitizes a single path segment.
 * Throws InvalidArchivePathError if the segment is invalid.
 */
function validatePathSegment(segment: string, fullPath: string): void {
  // Check for null bytes, control characters, and Unicode format characters
  if (UNSAFE_PATH_CHARS.test(segment)) {
    throw new InvalidArchivePathError(`Control or format characters not allowed in path segment "${segment}" of "${fullPath}"`);
  }

  // Check for colon (Windows drive separator, also invalid in filenames)
  if (segment.includes(':')) {
    throw new InvalidArchivePathError(`Colon not allowed in path segment "${segment}" of "${fullPath}"`);
  }

  // Check for Windows reserved names
  if (isWindowsReservedName(segment)) {
    throw new InvalidArchivePathError(`Windows reserved device name "${segment}" not allowed in "${fullPath}"`);
  }

  // Check for trailing dots or spaces (Windows strips these, causing ambiguity)
  if (segment.endsWith('.') || segment.endsWith(' ')) {
    throw new InvalidArchivePathError(`Path segment "${segment}" in "${fullPath}" ends with dot or space`);
  }

  // Maximum segment length (255 bytes is common filesystem limit)
  if (segment.length > 255) {
    throw new InvalidArchivePathError(`Path segment "${segment}" in "${fullPath}" exceeds 255 characters`);
  }
}

/**
 * Sanitizes and validates a file path to prevent directory traversal attacks,
 * invalid characters, and cross-platform ambiguities.
 *
 * @param rawPath The raw input path
 * @returns Sanitized path using forward slashes, no traversal, no reserved names
 * @throws InvalidArchivePathError if the path is invalid or unsafe
 */
export function sanitizeArchivePath(rawPath: string): string {
  if (typeof rawPath !== 'string') {
    throw new InvalidArchivePathError('Path must be a string');
  }

  // Remove null bytes, control characters, and Unicode format characters entirely
  let sanitized = rawPath.replace(UNSAFE_PATH_CHARS, '');

  // Replace backslashes with forward slashes
  sanitized = sanitized.replace(/\\/g, '/');

  // Strip drive letters like "C:" or "C:\"
  sanitized = sanitized.replace(/^[a-zA-Z]:/, '');

  // Strip leading slashes (absolute paths)
  sanitized = sanitized.replace(/^\/+/, '');

  // Split into path segments
  const segments = sanitized.split('/');

  const validatedSegments: string[] = [];
  for (const seg of segments) {
    const trimmed = seg.trim();

    // Skip empty segments and current-directory references
    if (trimmed.length === 0 || trimmed === '.') {
      continue;
    }

    // Reject parent-directory traversal
    if (trimmed === '..') {
      throw new InvalidArchivePathError(`Directory traversal ("..") not allowed in path "${rawPath}"`);
    }

    // Validate the segment
    validatePathSegment(trimmed, rawPath);

    validatedSegments.push(trimmed);
  }

  if (validatedSegments.length === 0) {
    return 'unnamed-file';
  }

  // Re-join with single forward slash
  return validatedSegments.join('/');
}

/**
 * Replaces a single path segment with a safe equivalent without rejecting it.
 * Used by the restore-time sanitizer so that legacy archives remain openable.
 */
function defusePathSegment(segment: string): string {
  let defused = segment.replace(/:/g, '_');
  // Windows strips trailing dots and spaces, which silently merges distinct names.
  defused = defused.replace(/[.\s]+$/, '');
  if (defused.length === 0) {
    return 'unnamed-file';
  }
  if (isWindowsReservedName(defused)) {
    defused = `_${defused}`;
  }
  if (defused.length > 255) {
    defused = defused.slice(0, 255);
  }
  return defused;
}

/**
 * Normalizes a path taken from an archive manifest at restore time.
 *
 * Unlike sanitizeArchivePath this never rejects the archive: the manifest is
 * cryptographically authenticated (bound as AES-256-GCM AAD) and may have been
 * written by an earlier release that accepted platform-ambiguous names. Those
 * archives must stay openable, so unsafe characters and ambiguous shapes are
 * defused instead of aborting the restore. Collisions introduced by defusing
 * are resolved by resolveUniquePaths, so no file is discarded or overwritten.
 */
export function restoreArchivePath(rawPath: string): string {
  if (typeof rawPath !== 'string') {
    return 'unnamed-file';
  }

  let sanitized = rawPath.replace(UNSAFE_PATH_CHARS, '');
  sanitized = sanitized.replace(/\\/g, '/');
  sanitized = sanitized.replace(/^[a-zA-Z]:/, '');
  sanitized = sanitized.replace(/^\/+/, '');

  const resolvedSegments: string[] = [];
  for (const seg of sanitized.split('/')) {
    const trimmed = seg.trim();
    // Drop empty, current-directory, and traversal segments rather than rejecting
    if (trimmed.length === 0 || trimmed === '.' || trimmed === '..') {
      continue;
    }
    resolvedSegments.push(defusePathSegment(trimmed));
  }

  if (resolvedSegments.length === 0) {
    return 'unnamed-file';
  }

  return resolvedSegments.join('/');
}

/** Normalizes a full path for cross-platform comparison. */
function normalizeFullPath(path: string): string {
  return path.split('/').map(normalizePathSegment).join('/');
}

/**
 * Detects a file-versus-directory conflict, comparing both literally and
 * case-insensitively so that collisions on case-insensitive filesystems
 * (Windows, macOS default) are also caught.
 */
function hasDirectoryConflict(a: string, b: string): boolean {
  if (a.startsWith(b + '/') || b.startsWith(a + '/')) {
    return true;
  }
  const normA = normalizeFullPath(a);
  const normB = normalizeFullPath(b);
  return normA.startsWith(normB + '/') || normB.startsWith(normA + '/');
}

/**
 * Ensures all paths in an archive are unique and non-conflicting across platforms.
 * Handles:
 * - Exact duplicates
 * - Case-insensitive collisions (e.g., "File.txt" vs "file.txt")
 * - Unicode normalization collisions (e.g., "café" vs "cafe\u0301")
 * - File vs directory conflicts (e.g., "folder/file.txt" vs "folder")
 * - Windows reserved names
 * - Trailing dots/spaces
 *
 * Appends " (1)", " (2)", etc. before the extension if conflicts occur.
 * Never silently discards files or overwrites content.
 *
 * @param entries Paths to resolve.
 * @param sanitize Sanitizer to apply first. Defaults to the strict
 *   sanitizeArchivePath (encryption-time input); pass restoreArchivePath to
 *   defuse rather than reject paths from an authenticated manifest.
 */
export function resolveUniquePaths(
  entries: { path: string }[],
  sanitize: (path: string) => string = sanitizeArchivePath
): string[] {
  // First pass: sanitize all paths
  const sanitizedPaths: string[] = [];
  for (let i = 0; i < entries.length; i++) {
    sanitizedPaths.push(sanitize(entries[i].path));
  }

  // Second pass: resolve conflicts, claiming normalized paths on first occurrence
  const seenPaths = new Set<string>();
  const seenNormalized = new Set<string>();
  const resolved: string[] = [];

  const conflictsWithSeen = (candidate: string): boolean => {
    if (seenPaths.has(candidate)) return true;
    if (seenNormalized.has(normalizeFullPath(candidate))) return true;
    for (const existing of seenPaths) {
      if (hasDirectoryConflict(candidate, existing)) return true;
    }
    return false;
  };

  for (let i = 0; i < sanitizedPaths.length; i++) {
    const cleanPath = sanitizedPaths[i];

    if (!conflictsWithSeen(cleanPath)) {
      // First occurrence - claim it
      seenPaths.add(cleanPath);
      seenNormalized.add(normalizeFullPath(cleanPath));
      resolved.push(cleanPath);
      continue;
    }

    // Conflict detected: build a unique variant.
    const lastSlash = cleanPath.lastIndexOf('/');
    const dir = lastSlash !== -1 ? cleanPath.substring(0, lastSlash + 1) : '';
    const filename = lastSlash !== -1 ? cleanPath.substring(lastSlash + 1) : cleanPath;

    const lastDot = filename.lastIndexOf('.');
    const baseName = lastDot !== -1 ? filename.substring(0, lastDot) : filename;
    const extension = lastDot !== -1 ? filename.substring(lastDot) : '';

    /**
     * Determines whether renaming the basename can ever resolve the conflict.
     * A directory-prefix conflict (e.g. "folder/file.txt" colliding with the
     * file "folder") cannot be fixed by renaming the basename, so the first
     * path segment must be renamed instead.
     */
    const isDirectoryPrefixConflictOnly = (value: string): boolean => {
      for (const existing of seenPaths) {
        const a = normalizeFullPath(value);
        const b = normalizeFullPath(existing);
        if (a.startsWith(b + '/') || b.startsWith(a + '/')) {
          return true;
        }
      }
      return false;
    };

    let counter = 1;
    let candidate = cleanPath;

    while (conflictsWithSeen(candidate)) {
      if (isDirectoryPrefixConflictOnly(candidate)) {
        // Rename the first path segment so the loop is guaranteed to terminate.
        const segments = cleanPath.split('/');
        segments[0] = `${segments[0]} (${counter})`;
        candidate = segments.join('/');
      } else {
        // Preferred variant: rename the basename, keeping the directory intact.
        candidate = `${dir}${baseName} (${counter})${extension}`;
      }
      counter++;
    }

    seenPaths.add(candidate);
    seenNormalized.add(normalizeFullPath(candidate));
    resolved.push(candidate);
  }

  return resolved;
}
