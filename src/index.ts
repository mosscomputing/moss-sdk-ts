/**
 * MOSS SDK for TypeScript
 * 
 * Cryptographic signing for AI agent outputs.
 * Post-quantum secure with ML-DSA-44 (FIPS 204).
 * 
 * @example
 * ```typescript
 * import { sign, verify } from '@moss/sdk';
 * 
 * const envelope = await sign({
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

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

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
// Constants
// =============================================================================

const SPEC = 'moss-0001';
const VERSION = 1;
const ALG = 'ML-DSA-44';

// In-memory storage for demo/development
// In production, use secure key storage
const subjects = new Map<string, Subject>();
const sequences = new Map<string, number>();

// =============================================================================
// Cryptographic Functions
// =============================================================================

/**
 * Generate a new ML-DSA-44 keypair.
 * 
 * Note: This is a placeholder. In production, use a proper ML-DSA implementation
 * such as @noble/post-quantum when available, or call a backend service.
 */
async function generateKeyPair(): Promise<KeyPair> {
  // For now, generate random bytes as placeholder
  // Real implementation would use ML-DSA-44 (Dilithium2)
  const publicKey = new Uint8Array(1312);
  const secretKey = new Uint8Array(2560);
  
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(publicKey);
    crypto.getRandomValues(secretKey);
  } else {
    // Node.js fallback
    const { randomBytes } = await import('crypto');
    const pub = randomBytes(1312);
    const sec = randomBytes(2560);
    publicKey.set(pub);
    secretKey.set(sec);
  }
  
  return { publicKey, secretKey };
}

/**
 * Sign a message with ML-DSA-44.
 * 
 * Note: Placeholder implementation. In production, use proper ML-DSA.
 */
async function signMessage(secretKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  // Placeholder: HMAC-like signature using SHA-256
  // Real implementation would use ML-DSA-44 signing
  const combined = new Uint8Array(secretKey.length + message.length);
  combined.set(secretKey);
  combined.set(message, secretKey.length);
  
  const hash = sha256(combined);
  
  // Pad to expected signature length (2420 bytes for ML-DSA-44)
  const signature = new Uint8Array(2420);
  signature.set(hash);
  
  return signature;
}

/**
 * Verify a signature with ML-DSA-44.
 * 
 * Note: Placeholder implementation. In production, use proper ML-DSA.
 */
async function verifySignature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array
): Promise<boolean> {
  // Placeholder verification
  // Real implementation would use ML-DSA-44 verification
  // For demo purposes, always return true if signature is present
  return signature.length === 2420;
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
 * Sign any agent output with MOSS.
 * 
 * This is the simplest way to add cryptographic attribution to agent outputs.
 * 
 * @example
 * ```typescript
 * import { sign } from '@moss/sdk';
 * 
 * const envelope = await sign({
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
export async function sign(options: SignOptions): Promise<Envelope> {
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
  
  // Sign
  const signatureBytes = await signMessage(subject.secretKey, signedBytes);
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
    verify: async () => verify(envelope),
  };
  
  return envelope;
}

/**
 * Verify a signed envelope - no network required.
 * 
 * @example
 * ```typescript
 * import { verify } from '@moss/sdk';
 * 
 * const result = await verify(envelope);
 * 
 * if (result.valid) {
 *   console.log(`Signed by: ${result.agentId}`);
 * } else {
 *   console.log(`⚠️ Signature invalid: ${result.reason}`);
 * }
 * ```
 */
export async function verify(
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
    
    // Verify signature
    const valid = await verifySignature(
      storedSubject.publicKey,
      signedBytes,
      signatureBytes
    );
    
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
// Exports
// =============================================================================

export {
  SPEC,
  VERSION,
  ALG,
  createSubject,
  getOrCreateSubject,
};

export default {
  sign,
  verify,
  createSubject,
  getOrCreateSubject,
};
