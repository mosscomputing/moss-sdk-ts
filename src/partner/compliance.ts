/**
 * MOSS Partner SDK — compliance.* resource namespace (parity with
 * moss-go/partner/compliance.go).
 *
 * ComplianceService.verifyReport is a client-side helper that locates the
 * %%MOSS-SIGNATURE-V1 marker in the PDF bytes, fetches the signer's public
 * key from /.well-known/moss-keys/{key_id}, and verifies the embedded
 * ML-DSA-44 signature. No backend verify route is called — only the public
 * keyset endpoint.
 */

import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { Client, RequestContext } from './client.js';
import { verifyMLDSA44 } from './mldsa_verify.js';

/**
 * ComplianceReport is the signed PDF bytes returned by
 * customers.complianceReport. The bytes carry the %%MOSS-SIGNATURE-V1 marker
 * and an embedded QR pointing at the offline verify page.
 */
export class ComplianceReport {
  /** Raw signed PDF bytes (%PDF- magic header). */
  readonly pdf: Uint8Array;
  /** Response Content-Type (application/pdf). */
  readonly contentType: string;

  constructor(contentType: string, pdf: Uint8Array) {
    this.contentType = contentType;
    this.pdf = pdf;
  }

  /**
   * Save writes the PDF bytes to the given path. The written file's first 4
   * bytes are %PDF. Returns the number of bytes written.
   */
  save(path: string): number {
    if (!this.pdf) throw new Error('moss: compliance report has no PDF bytes');
    const buf = Buffer.from(this.pdf);
    writeFileSync(path, buf);
    return buf.length;
  }

  /** hasSignatureMarker reports whether the PDF bytes contain the %%MOSS-SIGNATURE-V1 marker block. */
  hasSignatureMarker(): boolean {
    return includesBytes(this.pdf, stringToBytes('%%MOSS-SIGNATURE-V1'));
  }
}

/** VerifyResult is the client-side compliance.verifyReport result. */
export interface VerifyResult {
  valid: boolean;
  key_id?: string;
  signed_at?: string;
  /** Short diagnostic when valid is false (e.g. "no marker", "tampered"). */
  reason?: string;
}

/**
 * ComplianceService is the compliance.* resource namespace. It exposes the
 * client-side verifyReport helper (offline ML-DSA-44 signature-marker
 * verification).
 */
export class ComplianceService {
  private readonly c: Client;

  constructor(c: Client) {
    this.c = c;
  }

  /**
   * verifyReport is a client-side helper that locates the
   * %%MOSS-SIGNATURE-V1 marker in the PDF bytes, fetches the signer's public
   * key from /.well-known/moss-keys/{key_id}, and verifies the embedded
   * ML-DSA-44 signature. Returns {valid:true, key_id, signed_at?} for a
   * freshly fetched, untampered report. A tampered copy returns
   * {valid:false}. A PDF without the marker returns {valid:false} (not an
   * exception). No backend verify route is called — only the public keyset
   * endpoint.
   *
   * The helper is network-light: one GET to /.well-known/moss-keys/{key_id}.
   * It never sends the partner token (the keyset is public).
   */
  async verifyReport(
    ctx: RequestContext | undefined,
    pdf: Uint8Array,
  ): Promise<VerifyResult> {
    if (!pdf || pdf.length === 0) {
      return { valid: false, reason: 'empty pdf' };
    }
    let block: SignatureBlock;
    try {
      block = extractSignatureBlock(pdf);
    } catch (err) {
      return { valid: false, reason: (err as Error).message };
    }
    let pub: Uint8Array;
    try {
      pub = await this.c.fetchWellKnownKey(ctx, block.keyId);
    } catch (err) {
      return {
        valid: false,
        key_id: block.keyId,
        reason: 'public key fetch failed: ' + (err as Error).message,
      };
    }
    const ok = block.verify(pub);
    if (!ok) {
      return {
        valid: false,
        key_id: block.keyId,
        reason: 'signature mismatch (tampered)',
      };
    }
    return { valid: true, key_id: block.keyId, signed_at: block.signedAt };
  }
}

// ---- signature marker block ----

const SIG_MARKER_BEGIN = '%%MOSS-SIGNATURE-V1-BEGIN';
const SIG_MARKER_END = '%%MOSS-SIGNATURE-V1-END';

/**
 * SignatureBlock is the parsed %%MOSS-SIGNATURE-V1 marker block.
 *
 * The marker format (appended after %%EOF by embed_pdf_signature) is:
 *
 *   %%MOSS-SIGNATURE-V1 BEGIN
 *   key_id: <hex>
 *   signed_at: <iso-8601>
 *   alg: ML-DSA-44
 *   digest: <hex sha256 of the signed region (PDF bytes up to the BEGIN marker)>
 *   signature: <base64 ML-DSA-44 signature over the digest>
 *   %%MOSS-SIGNATURE-V1-END
 */
class SignatureBlock {
  keyId = '';
  signedAt = '';
  alg = '';
  digest = '';
  signature = '';
  /** PDF bytes up to (not including) the BEGIN marker. */
  signedRegion: Uint8Array = new Uint8Array(0);

  /** verify recomputes the sha256 digest of the signed region and verifies the ML-DSA-44 signature. */
  verify(publicKey: Uint8Array): boolean {
    if (!publicKey || publicKey.length === 0) return false;
    const sum = sha256Hex(this.signedRegion);
    if (!stringsEqualFold(sum, this.digest)) return false;
    const sigBytes = base64Decode(this.signature);
    return verifyMLDSA44(this.signedRegion, publicKey, sigBytes);
  }
}

function extractSignatureBlock(pdf: Uint8Array): SignatureBlock {
  const beginIdx = indexOfBytes(pdf, stringToBytes(SIG_MARKER_BEGIN));
  if (beginIdx < 0) throw new Error('no signature marker');
  const endIdx = indexOfBytes(pdf, stringToBytes(SIG_MARKER_END));
  if (endIdx < 0 || endIdx < beginIdx) {
    throw new Error('malformed signature marker (no end)');
  }
  const blockBytes = pdf.slice(beginIdx + SIG_MARKER_BEGIN.length, endIdx);
  const sb = new SignatureBlock();
  sb.signedRegion = pdf.slice(0, beginIdx);
  const text = bytesToString(blockBytes);
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (!line) continue;
    const idx = line.indexOf(':');
    if (idx < 0) continue;
    const k = line.slice(0, idx).trim();
    const v = line.slice(idx + 1).trim();
    switch (k) {
      case 'key_id':
        sb.keyId = v;
        break;
      case 'signed_at':
        sb.signedAt = v;
        break;
      case 'alg':
        sb.alg = v;
        break;
      case 'digest':
        sb.digest = v;
        break;
      case 'signature':
        sb.signature = v;
        break;
    }
  }
  if (!sb.keyId || !sb.digest || !sb.signature) {
    throw new Error('incomplete signature marker');
  }
  return sb;
}

// ---- byte helpers ----

function stringToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function bytesToString(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

function includesBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  return indexOfBytes(haystack, needle) >= 0;
}

function indexOfBytes(haystack: Uint8Array, needle: Uint8Array): number {
  if (needle.length === 0) return 0;
  if (haystack.length < needle.length) return -1;
  for (let i = 0; i <= haystack.length - needle.length; i++) {
    let match = true;
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) {
        match = false;
        break;
      }
    }
    if (match) return i;
  }
  return -1;
}

function sha256Hex(data: Uint8Array): string {
  return createHash('sha256').update(Buffer.from(data)).digest('hex');
}

function stringsEqualFold(a: string, b: string): boolean {
  if (a === b) return true;
  return a.toLowerCase() === b.toLowerCase();
}

function base64Decode(s: string): Uint8Array {
  const normalized = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  return new Uint8Array(Buffer.from(padded, 'base64'));
}
