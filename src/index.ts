/**
 * MOSS SDK for TypeScript
 * 
 * Cryptographic signing for AI agent outputs.
 * Post-quantum secure with ML-DSA-44 (FIPS 204).
 * 
 * @example
 * ```typescript
 * import { generateKeyPair, sign, verify } from '@moss/sdk';
 * 
 * const keyPair = await generateKeyPair();
 * const signature = await sign(payload, keyPair.secretKey);
 * const valid = await verify(payload, keyPair.publicKey, signature);
 * ```
 */

import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

// =============================================================================
// Types
// =============================================================================

export interface SignOptions {
  /** The agent output to sign (any JSON-serializable data) */
  output: unknown;
  /** Identifier for the agent (e.g., "agent-finance-01") */
  agentId: string;
  /** Optional context metadata */
  context?: Record<string, unknown>;
}

export interface Envelope {
  /** Protocol specification */
  spec: string;
  /** Envelope format version */
  version: number;
  /** Signing algorithm (ML-DSA-44) */
  alg: string;
  /** Agent/subject identifier */
  subject: string;
  /** Key version for rotation support */
  keyVersion: number;
  /** Sequence number */
  seq: number;
  /** Unix timestamp (seconds) */
  issuedAt: number;
  /** SHA-256 hash of the payload */
  payloadHash: string;
  /** Base64URL encoded signature */
  signature: string;
  /** Verify this envelope's signature */
  verify: () => Promise<VerifyResult>;
  /** Alias for subject */
  agentId: string;
  /** Alias for issuedAt */
  timestamp: number;
}

export interface VerifyResult {
  /** Whether the signature is valid */
  valid: boolean;
  /** The agent that signed (if valid) */
  subject?: string;
  /** Alias for subject */
  agentId?: string;
  /** Hash of the signed payload */
  payloadHash?: string;
  /** Error reason (if invalid) */
  reason?: string;
  /** Error code */
  errorCode?: string;
}

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface Subject {
  id: string;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
  keyVersion: number;
  seq: number;
}

// =============================================================================
// Enterprise Types
// =============================================================================

export interface HandshakeResult {
  /** Whether the agent is certified in MOSS Master Registry */
  isCertified: boolean;
  /** Certification status: 'certified' or 'unregistered' */
  certificationStatus: string;
  /** Organization ID */
  orgId?: string;
  /** Subscription tier */
  tier?: string;
  /** Error message if handshake failed */
  error?: string;
}

export interface SignResult {
  /** The cryptographic envelope */
  envelope: Envelope;
  /** Whether the agent is certified */
  isCertified: boolean;
  /** Certification status */
  certificationStatus: string;
}

// =============================================================================
// Constants
// =============================================================================

const SPEC = 'moss-0001';
const VERSION = 1;
const ALG = 'ML-DSA-44';
const SDK_VERSION = '0.1.0';

// Environment configuration
const MOSS_API_URL = typeof process !== 'undefined' 
  ? (process.env?.MOSS_API_URL || 'https://api.mosscomputing.com')
  : 'https://api.mosscomputing.com';

const MOSS_API_KEY = typeof process !== 'undefined'
  ? process.env?.MOSS_API_KEY
  : undefined;

// In-memory storage for development/demo ONLY.
// Keys are zeroed on removal. For production, use secure key management
// (vault, KMS, or hardware security module). Keys have no TTL — clear
// explicitly with clearSubjects() when done.
const subjects = new Map<string, Subject>();
const sequences = new Map<string, number>();

// Certification cache with 5-minute TTL
const certificationCache = new Map<string, { valid: boolean; expires: number }>();

// =============================================================================
// Cryptographic Functions (ML-DSA-44 / FIPS 204)
// =============================================================================

/**
 * Generate a new ML-DSA-44 keypair.
 *
 * Produces a keypair with the canonical FIPS 204 parameter sizes:
 * - publicKey: 1312 bytes
 * - secretKey: 2560 bytes
 *
 * Uses @noble/post-quantum ml-dsa-44 implementation.
 */
export async function generateKeyPair(): Promise<KeyPair> {
  const keyPair = ml_dsa44.keygen();
  return {
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey,
  };
}

/**
 * Sign a message with ML-DSA-44.
 *
 * Produces a 2420-byte post-quantum signature (FIPS 204 ML-DSA-44).
 *
 * @param payload - The message bytes to sign
 * @param secretKey - The ML-DSA-44 secret key (2560 bytes)
 * @returns A 2420-byte ML-DSA-44 signature
 */
export async function sign(payload: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
  return ml_dsa44.sign(payload, secretKey);
}

/**
 * Verify a signature with ML-DSA-44.
 *
 * @param payload - The original message bytes
 * @param publicKey - The ML-DSA-44 public key (1312 bytes)
 * @param signature - The 2420-byte ML-DSA-44 signature to verify
 * @returns true if the signature is valid, false otherwise
 */
export async function verify(payload: Uint8Array, publicKey: Uint8Array, signature: Uint8Array): Promise<boolean> {
  return ml_dsa44.verify(signature, payload, publicKey);
}

// =============================================================================
// Encoding Utilities
// =============================================================================

function base64UrlEncode(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);
  return new Uint8Array([...binary].map(c => c.charCodeAt(0)));
}

function canonicalJson(obj: unknown): string {
  return JSON.stringify(obj, Object.keys(obj as object).sort());
}

function computePayloadHash(payload: unknown): string {
  const canonical = canonicalJson(payload);
  const hash = sha256(new TextEncoder().encode(canonical));
  return 'sha256:' + bytesToHex(hash);
}

// =============================================================================
// Subject Management
// =============================================================================

/**
 * Create a new subject (agent identity) with fresh keys.
 */
export async function createSubject(agentId: string): Promise<Subject> {
  // Normalize to MOSS subject format
  const id = agentId.startsWith('moss:') ? agentId : `moss:agent:${agentId}`;
  
  const keyPair = await generateKeyPair();
  
  const subject: Subject = {
    id,
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey,
    keyVersion: 1,
    seq: 0,
  };
  
  subjects.set(id, subject);
  sequences.set(id, 0);
  
  return subject;
}

/**
 * Load an existing subject or create a new one.
 */
export async function getOrCreateSubject(agentId: string): Promise<Subject> {
  const id = agentId.startsWith('moss:') ? agentId : `moss:agent:${agentId}`;
  
  let subject = subjects.get(id);
  if (!subject) {
    subject = await createSubject(id);
  }
  
  return subject;
}

// =============================================================================
// Main API
// =============================================================================

/**
 * Sign any agent output with MOSS, producing a cryptographic envelope.
 * 
 * This is the simplest way to add cryptographic attribution to agent outputs.
 * The envelope contains a real ML-DSA-44 (FIPS 204) post-quantum signature.
 * 
 * @example
 * ```typescript
 * import { signEnvelope } from '@moss/sdk';
 * 
 * const envelope = await signEnvelope({
 *   output: agentResponse,
 *   agentId: "agent-finance-01",
 *   context: { userId: user.id, action: "transfer" }
 * });
 * 
 * // envelope.signature: ML-DSA-44 post-quantum signature
 * // envelope.timestamp: Signed timestamp
 * // envelope.verify(): Returns true if untampered
 * ```
 */
export async function signEnvelope(options: SignOptions): Promise<Envelope> {
  const { output, agentId, context } = options;
  
  // Get or create subject
  const subject = await getOrCreateSubject(agentId);
  
  // Increment sequence
  const seq = (sequences.get(subject.id) ?? 0) + 1;
  sequences.set(subject.id, seq);
  
  // Build payload
  const payload = typeof output === 'object' && output !== null
    ? { ...output as object }
    : { output };
  
  if (context) {
    (payload as Record<string, unknown>)._context = context;
  }
  
  // Compute payload hash
  const payloadHash = computePayloadHash(payload);
  const issuedAt = Math.floor(Date.now() / 1000);
  
  // Build signed bytes
  const signedBytesObj = {
    spec: SPEC,
    version: VERSION,
    alg: ALG,
    subject: subject.id,
    keyVersion: subject.keyVersion,
    seq,
    issuedAt,
    payloadHash,
  };
  
  const signedBytes = new TextEncoder().encode(canonicalJson(signedBytesObj));
  
  // Sign with real ML-DSA-44
  const signatureBytes = await sign(signedBytes, subject.secretKey);
  const signature = base64UrlEncode(signatureBytes);
  
  // Create envelope with verify method
  const envelope: Envelope = {
    spec: SPEC,
    version: VERSION,
    alg: ALG,
    subject: subject.id,
    keyVersion: subject.keyVersion,
    seq,
    issuedAt,
    payloadHash,
    signature,
    // Convenience properties
    get agentId() { return this.subject; },
    get timestamp() { return this.issuedAt; },
    // Verify method
    verify: async () => verifyEnvelope(envelope),
  };
  
  return envelope;
}

/**
 * Verify a signed envelope - no network required.
 * 
 * @example
 * ```typescript
 * import { verifyEnvelope } from '@moss/sdk';
 * 
 * const result = await verifyEnvelope(envelope);
 * 
 * if (result.valid) {
 *   console.log(`Signed by: ${result.agentId}`);
 * } else {
 *   console.log(`⚠️ Signature invalid: ${result.reason}`);
 * }
 * ```
 */
export async function verifyEnvelope(
  envelope: Envelope | Record<string, unknown>
): Promise<VerifyResult> {
  try {
    // Extract envelope fields
    const {
      spec,
      version,
      alg,
      subject,
      keyVersion,
      seq,
      issuedAt,
      payloadHash,
      signature,
    } = envelope as Envelope;
    
    // Validate spec
    if (spec !== SPEC) {
      return {
        valid: false,
        reason: `Unknown spec: ${spec}`,
        errorCode: 'MOSS_ERR_003',
      };
    }
    
    // Get subject's public key
    const storedSubject = subjects.get(subject);
    if (!storedSubject) {
      return {
        valid: false,
        subject,
        reason: `Unknown subject: ${subject}`,
        errorCode: 'MOSS_ERR_002',
      };
    }
    
    // Rebuild signed bytes
    const signedBytesObj = {
      spec,
      version,
      alg,
      subject,
      keyVersion,
      seq,
      issuedAt,
      payloadHash,
    };
    
    const signedBytes = new TextEncoder().encode(canonicalJson(signedBytesObj));
    const signatureBytes = base64UrlDecode(signature);
    
    // Verify signature with real ML-DSA-44
    const valid = await verify(signedBytes, storedSubject.publicKey, signatureBytes);
    
    if (!valid) {
      return {
        valid: false,
        subject,
        agentId: subject,
        reason: 'Invalid signature',
        errorCode: 'MOSS_ERR_004',
      };
    }
    
    return {
      valid: true,
      subject,
      agentId: subject,
      payloadHash,
    };
  } catch (error) {
    return {
      valid: false,
      reason: `Verification error: ${error instanceof Error ? error.message : String(error)}`,
      errorCode: 'MOSS_ERR_000',
    };
  }
}

// =============================================================================
// Enterprise Functions
// =============================================================================

/**
 * Check if enterprise mode is enabled.
 */
export function isEnterpriseMode(): boolean {
  return !!MOSS_API_KEY;
}

/**
 * Perform registry handshake to check agent certification.
 * 
 * This validates the API key and checks if the agent is registered
 * in the MOSS Master Registry. Only certified agents can have
 * signatures marked as isCertified: true.
 * 
 * @example
 * ```typescript
 * const result = await handshake("my-agent");
 * if (result.isCertified) {
 *   console.log("Agent is certified!");
 * }
 * ```
 */
export async function handshake(agentId: string): Promise<HandshakeResult> {
  if (!isEnterpriseMode()) {
    return {
      isCertified: false,
      certificationStatus: 'unregistered',
      error: 'Enterprise mode not enabled (MOSS_API_KEY not set)',
    };
  }

  // Check cache (with TTL)
  const cached = certificationCache.get(agentId);
  if (cached && cached.expires > Date.now()) {
    return {
      isCertified: cached.valid,
      certificationStatus: cached.valid ? 'certified' : 'unregistered',
    };
  }
  if (cached) {
    certificationCache.delete(agentId); // expired
  }

  try {
    const response = await fetch(`${MOSS_API_URL}/v1/registry/handshake`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${MOSS_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        agent_id: agentId,
        sdk_version: SDK_VERSION,
        sdk_language: 'typescript',
      }),
    });

    if (!response.ok) {
      return {
        isCertified: false,
        certificationStatus: 'unregistered',
        error: `API error: ${response.status}`,
      };
    }

    const data = await response.json();
    const isCertified = data.is_certified || false;
    
    // Cache the result with 5-minute TTL
    certificationCache.set(agentId, { valid: isCertified, expires: Date.now() + 5 * 60 * 1000 });

    return {
      isCertified,
      certificationStatus: data.certification_status || 'unregistered',
      orgId: data.org_id,
      tier: data.tier,
    };
  } catch (error) {
    return {
      isCertified: false,
      certificationStatus: 'unregistered',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Check if an agent is certified (from cache).
 */
export function isAgentCertified(agentId: string): boolean {
  const cached = certificationCache.get(agentId);
  if (!cached || cached.expires <= Date.now()) {
    return false;
  }
  return cached.valid;
}

/**
 * Clear the certification cache.
 */
export function clearCertificationCache(): void {
  certificationCache.clear();
}

/**
 * Remove a subject and zero its secret key from memory.
 * Call this when done with a key to prevent memory extraction.
 */
export function removeSubject(subjectId: string): boolean {
  const subject = subjects.get(subjectId);
  if (subject) {
    // Zero the secret key bytes before removing
    subject.secretKey.fill(0);
    subjects.delete(subjectId);
    return true;
  }
  return false;
}

/**
 * Remove all subjects and zero their secret keys.
 */
export function clearSubjects(): void {
  for (const subject of subjects.values()) {
    subject.secretKey.fill(0);
  }
  subjects.clear();
  sequences.clear();
}

/**
 * Sign with enterprise features - returns SignResult with certification status.
 * 
 * @example
 * ```typescript
 * const result = await signWithCertification({
 *   output: agentResponse,
 *   agentId: "my-agent"
 * });
 * 
 * console.log(`Certified: ${result.isCertified}`);
 * console.log(`Signature: ${result.envelope.signature}`);
 * ```
 */
export async function signWithCertification(options: SignOptions): Promise<SignResult> {
  const envelope = await signEnvelope(options);
  
  // Check certification
  let isCertified = false;
  let certificationStatus = 'unregistered';
  
  if (isEnterpriseMode()) {
    const handshakeResult = await handshake(options.agentId);
    isCertified = handshakeResult.isCertified;
    certificationStatus = handshakeResult.certificationStatus;
  }
  
  return {
    envelope,
    isCertified,
    certificationStatus,
  };
}

// =============================================================================
// Exports
// =============================================================================

export {
  SPEC,
  VERSION,
  ALG,
  SDK_VERSION,
};

export default {
  generateKeyPair,
  sign,
  verify,
  signEnvelope,
  verifyEnvelope,
  signWithCertification,
  handshake,
  isEnterpriseMode,
  isAgentCertified,
  clearCertificationCache,
  createSubject,
  getOrCreateSubject,
};
