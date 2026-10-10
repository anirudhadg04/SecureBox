export class EnvelopeError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'EnvelopeError';
    Object.setPrototypeOf(this, EnvelopeError.prototype);
  }
}

export class InvalidMagicBytesError extends EnvelopeError {
  constructor(message = 'Invalid file format: file does not have the SecureBox "SBOX" signature') {
    super(message);
    this.name = 'InvalidMagicBytesError';
    Object.setPrototypeOf(this, InvalidMagicBytesError.prototype);
  }
}

export class UnsupportedVersionError extends EnvelopeError {
  constructor(version: number) {
    super(`Unsupported SecureBox envelope version: ${version}`);
    this.name = 'UnsupportedVersionError';
    Object.setPrototypeOf(this, UnsupportedVersionError.prototype);
  }
}

export class UnsupportedAlgorithmError extends EnvelopeError {
  constructor(algoId: number) {
    super(`Unsupported algorithm identifier: ${algoId}`);
    this.name = 'UnsupportedAlgorithmError';
    Object.setPrototypeOf(this, UnsupportedAlgorithmError.prototype);
  }
}

export class EnvelopeTruncatedError extends EnvelopeError {
  constructor(message = 'The encrypted file is truncated or damaged') {
    super(message);
    this.name = 'EnvelopeTruncatedError';
    Object.setPrototypeOf(this, EnvelopeTruncatedError.prototype);
  }
}

export class InvalidMetadataError extends EnvelopeError {
  constructor(message = 'Metadata header is malformed or invalid', cause?: unknown) {
    super(message, cause);
    this.name = 'InvalidMetadataError';
    Object.setPrototypeOf(this, InvalidMetadataError.prototype);
  }
}

export class InvalidArchiveManifestError extends EnvelopeError {
  constructor(message = 'Archive manifest header is malformed, invalid, or corrupted', cause?: unknown) {
    super(message, cause);
    this.name = 'InvalidArchiveManifestError';
    Object.setPrototypeOf(this, InvalidArchiveManifestError.prototype);
  }
}

export class ArchiveIntegrityMismatchError extends EnvelopeError {
  constructor(message = 'Archive file payload integrity check failed (SHA-256 mismatch or invalid offset/size)') {
    super(message);
    this.name = 'ArchiveIntegrityMismatchError';
    Object.setPrototypeOf(this, ArchiveIntegrityMismatchError.prototype);
  }
}

export class InvalidManifestIntegerError extends EnvelopeError {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidManifestIntegerError';
    Object.setPrototypeOf(this, InvalidManifestIntegerError.prototype);
  }
}

export class ManifestFileCountMismatchError extends EnvelopeError {
  constructor(message: string) {
    super(message);
    this.name = 'ManifestFileCountMismatchError';
    Object.setPrototypeOf(this, ManifestFileCountMismatchError.prototype);
  }
}

export class ManifestEntryBoundsError extends EnvelopeError {
  constructor(message: string) {
    super(message);
    this.name = 'ManifestEntryBoundsError';
    Object.setPrototypeOf(this, ManifestEntryBoundsError.prototype);
  }
}

export class ManifestNonContiguousError extends EnvelopeError {
  constructor(message: string) {
    super(message);
    this.name = 'ManifestNonContiguousError';
    Object.setPrototypeOf(this, ManifestNonContiguousError.prototype);
  }
}

export class InvalidArchivePathError extends EnvelopeError {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidArchivePathError';
    Object.setPrototypeOf(this, InvalidArchivePathError.prototype);
  }
}

export class MetadataSizeMismatchError extends EnvelopeError {
  constructor(message: string) {
    super(message);
    this.name = 'MetadataSizeMismatchError';
    Object.setPrototypeOf(this, MetadataSizeMismatchError.prototype);
  }
}
