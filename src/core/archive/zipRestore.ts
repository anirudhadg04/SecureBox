import JSZip from 'jszip';
import { RestoredArchiveFile } from './types';

/**
 * Packages restored archive files into a standard, downloadable ZIP container.
 * Places all files inside a designated top-level directory so the ZIP extracts
 * cleanly into a single folder without polluting the user's download directory.
 *
 * @param files Array of restored files with sanitized, unique paths.
 * @param archiveName Base name of the archive (used for root folder and filename).
 * @returns Standard ZIP Blob ready for browser download.
 */
export async function createRestoredZipBlob(
  files: RestoredArchiveFile[],
  archiveName: string = 'securebox-archive'
): Promise<Blob> {
  const zip = new JSZip();

  // Clean root folder name
  const safeRootFolder = archiveName.replace(/\.sbox$/i, '').replace(/[^a-zA-Z0-9_\-]/g, '_') || 'securebox-restored';
  const folder = zip.folder(safeRootFolder);

  if (!folder) {
    throw new Error('Failed to create root folder in ZIP archive');
  }

  for (const file of files) {
    // Add file to ZIP preserving relative path structure
    folder.file(file.path, file.data);
  }

  return await zip.generateAsync({
    type: 'blob',
    compression: 'DEFLATE',
    compressionOptions: {
      level: 6,
    },
  });
}
