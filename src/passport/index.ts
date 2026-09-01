/**
 * MOSS Passport SDK — Self-service Agent Passport entry point (MOSS 2.0).
 *
 * Static functions for the self-service signup flow. No authentication
 * required — these call the public MOSS API endpoints.
 *
 * Usage:
 *   import { MOSS } from '@moss/sdk/passport';
 *
 *   // Step 1: Register (sends OTP email)
 *   const reg = await MOSS.register({
 *     email: 'dev@example.com',
 *     agentSubject: 'my-agent',
 *   });
 *
 *   // Step 2: Verify OTP code
 *   const verified = await MOSS.verify({
 *     email: 'dev@example.com',
 *     otpCode: '123456',
 *     orgId: reg.orgId,
 *   });
 *   // verified.customerToken -> cust_xxx
 *   // verified.passport -> full passport JSON
 *
 *   // Step 3: Use the customer token
 *   import { newCustomerClient } from '@moss/sdk/customer';
 *   const client = newCustomerClient({ token: verified.customerToken });
 *   const passports = await client.passports.list(ctx);
 *
 *   // Verify a passport signature (no auth needed)
 *   const result = await verifyPassport(passportJson);
 *   // result.valid -> true if signature is valid
 */

export interface RegisterRequest {
  email: string;
  agentSubject: string;
  capabilities?: string[];
  agentDisplayName?: string;
  signupSource?: string;
}

export interface RegisterResponse {
  org_id: string | null;
  verification_required: boolean;
  message: string;
}

export interface VerifyRequest {
  email: string;
  otpCode: string;
  orgId?: string | null;
}

export interface VerifyResponse {
  customer_token: string;
  passport: Passport;
  verification_url: string;
  sdk_command: string;
}

export interface Passport {
  version: string;
  passport_id: string;
  agent_subject: string;
  agent_display_name: string | null;
  owner_org_name: string;
  capabilities: string[];
  policy_scope: Record<string, unknown>;
  issued_at: string;
  expires_at: string;
  revocation_url: string;
  verification_url: string;
  hash: string;
  signature: string;
  signing_key_id: string;
}

export interface PassportVerificationResult {
  valid: boolean;
  expired: boolean;
  expires_at: string;
  signer: string;
  key_id: string;
  error?: string;
}

const DEFAULT_BASE_URL = 'https://api.mosscomputing.com';
const SDK_VERSION = '0.3.0';

function normalizeBaseUrl(baseURL?: string): string {
  return (baseURL || DEFAULT_BASE_URL).replace(/\/+$/, '');
}

export const MOSS = {
  /**
   * Register for a free Agent Passport (sends OTP email).
   * No authentication required — calls the public endpoint.
   */
  async register(
    req: RegisterRequest,
    opts?: { baseURL?: string }
  ): Promise<RegisterResponse> {
    const url = normalizeBaseUrl(opts?.baseURL);
    const res = await fetch(`${url}/v1/passport/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': `moss-sdk-ts/${SDK_VERSION}`,
      },
      body: JSON.stringify({
        email: req.email,
        agent_subject: req.agentSubject,
        capabilities: req.capabilities || [],
        agent_display_name: req.agentDisplayName,
        signup_source: req.signupSource || 'direct',
      }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(`Registration failed (${res.status}): ${JSON.stringify(body)}`);
    }
    return res.json();
  },

  /**
   * Verify OTP code and create org + agent + passport.
   * No authentication required — calls the public endpoint.
   */
  async verify(
    req: VerifyRequest,
    opts?: { baseURL?: string }
  ): Promise<VerifyResponse> {
    const url = normalizeBaseUrl(opts?.baseURL);
    const res = await fetch(`${url}/v1/passport/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': `moss-sdk-ts/${SDK_VERSION}`,
      },
      body: JSON.stringify({
        email: req.email,
        otp_code: req.otpCode,
        org_id: req.orgId,
      }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(`Verification failed (${res.status}): ${JSON.stringify(body)}`);
    }
    return res.json();
  },
};

/**
 * Verify a passport's ML-DSA-44 signature locally.
 * Fetches the public key from the MOSS well-known endpoint and verifies
 * the signature using @noble/post-quantum.
 */
export async function verifyPassport(
  passport: Passport,
  opts?: { baseURL?: string }
): Promise<PassportVerificationResult> {
  const keyId = passport.signing_key_id;
  const signatureField = passport.signature || '';

  // Parse signature (format: "ml_dsa_44:<base64>")
  const signatureB64 = signatureField.startsWith('ml_dsa_44:')
    ? signatureField.slice('ml_dsa_44:'.length)
    : signatureField;

  // Build payload without signature fields for verification
  const payload: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(passport)) {
    if (k !== 'hash' && k !== 'signature' && k !== 'signing_key_id') {
      payload[k] = v;
    }
  }

  // Canonical encoding (RFC-8785-shaped)
  const canonical = new TextEncoder().encode(
    JSON.stringify(payload, Object.keys(payload).sort())
  );

  try {
    // Fetch public key from well-known endpoint
    const url = normalizeBaseUrl(opts?.baseURL);
    const keyRes = await fetch(`${url}/.well-known/moss-keys/${keyId}`, {
      headers: { 'User-Agent': `moss-sdk-ts/${SDK_VERSION}` },
    });
    if (!keyRes.ok) {
      return {
        valid: false,
        expired: false,
        expires_at: passport.expires_at,
        signer: 'unknown',
        key_id: keyId,
        error: 'public_key_not_found',
      };
    }
    const keyData = await keyRes.json();
    const pkHex = keyData.public_key_hex || '';
    if (!pkHex) {
      return {
        valid: false,
        expired: false,
        expires_at: passport.expires_at,
        signer: 'unknown',
        key_id: keyId,
        error: 'public_key_not_found',
      };
    }

    // Convert hex to bytes
    const publicKey = new Uint8Array(
      (pkHex.match(/.{1,2}/g) || []).map((b: string) => parseInt(b, 16))
    );

    // Decode base64 signature
    const signature = new Uint8Array(
      atob(signatureB64)
        .split('')
        .map((c) => c.charCodeAt(0))
    );

    // Verify using @noble/post-quantum
    const { ml_dsa44 } = await import('@noble/post-quantum/ml-dsa.js');
    const isValid = ml_dsa44.verify(publicKey, canonical, signature);

    // Check expiry
    let expired = false;
    if (passport.expires_at) {
      const exp = new Date(passport.expires_at);
      expired = Date.now() >= exp.getTime();
    }

    return {
      valid: isValid,
      expired,
      expires_at: passport.expires_at,
      signer: isValid ? 'moss' : 'unknown',
      key_id: keyId,
    };
  } catch (err) {
    return {
      valid: false,
      expired: false,
      expires_at: passport.expires_at,
      signer: 'unknown',
      key_id: keyId,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
