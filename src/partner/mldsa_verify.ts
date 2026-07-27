/**
 * MOSS Partner SDK — ML-DSA-44 signature verification helper.
 *
 * Used by ComplianceService.verifyReport for offline compliance-PDF signature
 * verification. Signing is server-side only — the SDK only verifies.
 *
 * Uses @noble/post-quantum ml-dsa-44 (FIPS 204), the same library the
 * existing runtime SDK (src/index.ts) uses for envelope signing.
 */

import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';

/**
 * verifyMLDSA44 verifies an ML-DSA-44 signature over msg against the public
 * key bytes (1312-byte raw public key). Returns false if the key/signature
 * sizes are wrong or verification fails. Never throws.
 */
export function verifyMLDSA44(
  msg: Uint8Array,
  publicKey: Uint8Array,
  signature: Uint8Array,
): boolean {
  // ML-DSA-44 canonical sizes (FIPS 204).
  if (publicKey.length !== 1312 || signature.length !== 2420) return false;
  try {
    return ml_dsa44.verify(signature, msg, publicKey);
  } catch {
    return false;
  }
}
