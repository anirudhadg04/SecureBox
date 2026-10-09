export interface HashComparisonResult {
  match: boolean;
  canonicalComputed: string;
  canonicalReference: string;
  differingIndices: number[];
}

/**
 * Normalizes a cryptographic hash string by removing all whitespace,
 * formatting delimiters (such as colons or dashes), and converting to lowercase.
 */
export function canonicalizeHash(input: string): string {
  return input.trim().toLowerCase().replace(/[^0-9a-f]/g, '');
}

/**
 * Compares two SHA-256 hashes for equality and provides character-level diff diagnostics.
 *
 * @param computed The freshly computed hash.
 * @param reference The reference hash provided for verification.
 */
export function compareHashes(computed: string, reference: string): HashComparisonResult {
  const canonicalComputed = canonicalizeHash(computed);
  const canonicalReference = canonicalizeHash(reference);

  const differingIndices: number[] = [];
  const maxLen = Math.max(canonicalComputed.length, canonicalReference.length);

  for (let i = 0; i < maxLen; i++) {
    if (canonicalComputed[i] !== canonicalReference[i]) {
      differingIndices.push(i);
    }
  }

  const match = canonicalComputed.length === 64 &&
    canonicalReference.length === 64 &&
    differingIndices.length === 0;

  return {
    match,
    canonicalComputed,
    canonicalReference,
    differingIndices,
  };
}
