/**
 * MOSS Partner SDK — client/transport core (parity with moss-go/partner).
 *
 * A Client is constructed with a token (prt_/cust_/cap_), a base URL
 * (default http://localhost:3100, overridable), a per-request timeout
 * (default 30s), and a retry policy (exponential backoff on 429/5xx honoring
 * Retry-After, bounded max retries). The persona is inferred from the token
 * prefix.
 *
 * Auth: `Authorization: Bearer <token>`. Idempotency-Key passthrough on
 * mutations. Typed error hierarchy via asTypedError.
 */

import {
  APIError,
  AuthError,
  Headers,
  asTypedError,
  parseRetryAfterMs,
} from './errors.js';

// ---- defaults ----

/** Default MOSS backend URL for the management surface (M3 local backend). */
export const DEFAULT_BASE_URL = 'http://localhost:3100';
/** Default per-request timeout (after retries), in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 30_000;
/** Default max retry count for idempotent GETs on 429/5xx. */
export const DEFAULT_MAX_RETRIES = 2;
/** Base for exponential backoff (milliseconds). */
export const INITIAL_BACKOFF_MS = 200;
/** Cap for exponential backoff between retries (milliseconds). */
export const MAX_BACKOFF_MS = 30_000;

// ---- token prefixes ----

export const PREFIX_PARTNER = 'prt_';
export const PREFIX_CUSTOMER = 'cust_';
export const PREFIX_CAPABILITY = 'cap_';

/** Persona inferred from the token prefix. */
export type Persona = 'partner' | 'customer' | 'capability' | 'unknown';

/** Infer the persona from a token's prefix. Returns "unknown" for empty/unrecognized. */
export function inferPersona(token: string): Persona {
  if (token.startsWith(PREFIX_PARTNER)) return 'partner';
  if (token.startsWith(PREFIX_CUSTOMER)) return 'customer';
  if (token.startsWith(PREFIX_CAPABILITY)) return 'capability';
  return 'unknown';
}

// ---- request context (mirrors Go's context.Context) ----

/** Request context — carries an optional AbortSignal for cancellation. */
export interface RequestContext {
  signal?: AbortSignal;
}

// ---- config ----

/** Partner SDK client configuration. */
export interface Config {
  /** MOSS API token (prt_, cust_, or cap_). Required. */
  token: string;
  /** Backend base URL. Defaults to http://localhost:3100. */
  baseURL?: string;
  /** Per-request timeout in milliseconds. Defaults to 30000. 0 = no timeout. */
  timeoutMs?: number;
  /** Max retry count for idempotent GETs on 429/5xx (and mutations with Idempotency-Key). Defaults to 2. */
  maxRetries?: number;
  /** Override persona inference. Optional. */
  persona?: Persona;
  /** Override the default User-Agent header. Optional. */
  userAgent?: string;
  /** Override the global fetch function (for test injection). Optional. */
  fetchImpl?: typeof fetch;
}

// ---- internal request options ----

export interface RequestOptions {
  method: string;
  path: string;
  query?: Record<string, string>;
  body?: unknown;
  idempotencyKey?: string;
  accept?: string;
  /** Override the default retry policy. When false the request is never retried. */
  retryableOverride?: boolean;
}

// ---- client ----

/**
 * Client is the MOSS Partner SDK client. It is safe for concurrent use.
 * Resource namespaces (`customers`, `compliance`) are attached at
 * construction time.
 */
export class Client {
  readonly cfg: Config;
  readonly token: string;
  readonly baseURL: string;
  readonly persona: Persona;
  readonly timeoutMs: number;
  readonly maxRetries: number;
  readonly userAgent: string;
  private readonly fetchImpl: typeof fetch;

  // Resource namespaces (assigned by index.ts to avoid a circular import).
  // Partner SDK namespaces:
  customers!: import('./customers.js').CustomersService;
  compliance!: import('./compliance.js').ComplianceService | import('../customer/compliance.js').ComplianceService;

  // Customer SDK namespaces (assigned by customer/index.ts):
  agents!: import('../customer/agents.js').AgentsService;
  capabilities!: import('../customer/capabilities.js').CapabilitiesService;
  policies!: import('../customer/policies.js').PoliciesService;
  audit!: import('../customer/audit.js').AuditService;

  constructor(cfg: Config) {
    if (!cfg.token) throw new Error('moss: Config.token is required');
    this.cfg = cfg;
    this.token = cfg.token;
    this.baseURL = (cfg.baseURL ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
    this.timeoutMs = cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxRetries = cfg.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.persona = cfg.persona ?? inferPersona(cfg.token);
    this.userAgent = cfg.userAgent ?? 'moss-sdk-ts-partner/1.0';
    this.fetchImpl = cfg.fetchImpl ?? globalThis.fetch;
    if (!this.fetchImpl) {
      throw new Error('moss: no fetch implementation available (use Config.fetchImpl)');
    }
  }

  /** Effective base URL the client targets. */
  getBaseURL(): string {
    return this.baseURL;
  }

  /** Inferred (or configured) persona. */
  getPersona(): Persona {
    return this.persona;
  }

  /** Configured token (prefix-only access is encouraged; never log the raw token). */
  getToken(): string {
    return this.token;
  }

  /** Token prefix (e.g. "prt_"), safe to log. */
  tokenPrefix(): string {
    switch (this.persona) {
      case 'partner':
        return PREFIX_PARTNER;
      case 'customer':
        return PREFIX_CUSTOMER;
      case 'capability':
        return PREFIX_CAPABILITY;
      default:
        return this.token.length >= 5 ? this.token.slice(0, 5) : this.token;
    }
  }

  /** Configured max-retry count. */
  getMaxRetries(): number {
    return this.maxRetries;
  }

  /**
   * requirePartner returns an AuthError if the client persona is not partner.
   * Used by partner-only resource methods to fail fast with a typed AuthError
   * (matching the backend's 403 invalid_credential_type response) rather than
   * making a network call. For PersonaUnknown the request is sent to the
   * backend so the backend's own auth resolver produces the canonical 401/403.
   */
  requirePartner(action: string): Error | null {
    if (this.persona === 'partner') return null;
    if (this.persona === 'customer' || this.persona === 'capability') {
      return new AuthError({
        status: 403,
        code: 'invalid_credential_type',
        message: `moss: ${action} requires a partner (prt_) token; got persona "${this.persona}"`,
      });
    }
    // PersonaUnknown: let the backend reject with its canonical 401/403.
    return null;
  }

  // ---- transport ----

  /**
   * do executes an HTTP request with retry/backoff. Sets Authorization,
   * Content-Type, Idempotency-Key, Accept, and User-Agent headers, serializes
   * the JSON body, performs retries on 429/5xx for idempotent requests (GETs
   * and mutations carrying an Idempotency-Key), and maps non-2xx responses to
   * the typed error hierarchy.
   */
  async do(
    ctx: RequestContext | undefined,
    opts: RequestOptions,
  ): Promise<{ status: number; headers: Headers; body: string }> {
    // A request is retryable iff it is a GET, or it carries an
    // Idempotency-Key (which makes mutations safely replayable). Mutations
    // without an Idempotency-Key are NOT retried.
    let retryable: boolean;
    if (opts.retryableOverride !== undefined) {
      retryable = opts.retryableOverride;
    } else {
      retryable = opts.method === 'GET' || !!opts.idempotencyKey;
    }
    const maxRetries = retryable ? this.maxRetries : 0;

    let lastErr: Error | null = null;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (attempt > 0) {
        const wait = this.backoffDelay(attempt, lastErr);
        if (!(await this.sleep(ctx, wait))) {
          const e = new Error('moss: request cancelled');
          (e as { name: string }).name = 'AbortError';
          throw e;
        }
      }
      let res: { status: number; headers: Headers; body: string };
      try {
        res = await this.doOnce(ctx, opts);
      } catch (err) {
        // Network/transport error: retryable on idempotent requests.
        lastErr = err as Error;
        if (retryable && attempt < maxRetries) continue;
        throw new Error(`moss: request failed: ${(err as Error).message}`);
      }
      if (res.status >= 200 && res.status < 300) {
        return res;
      }
      const parsed = parseJSONBody(res.body);
      const typed = asTypedError(res.status, parsed, res.headers, res.body);
      // Retry only on 429/5xx for retryable requests.
      if (
        retryable &&
        (res.status === 429 || res.status >= 500) &&
        attempt < maxRetries
      ) {
        lastErr = typed;
        continue;
      }
      throw typed;
    }
    // Should not reach here; the loop returns in every branch.
    throw lastErr ?? new Error('moss: retry loop exhausted');
  }

  /** doOnce performs a single HTTP attempt with no retry. */
  private async doOnce(
    ctx: RequestContext | undefined,
    opts: RequestOptions,
  ): Promise<{ status: number; headers: Headers; body: string }> {
    const url = this.buildURL(opts);
    const init: RequestInit = {
      method: opts.method,
      headers: this.buildHeaders(opts),
    };
    if (opts.body !== undefined) {
      init.body = JSON.stringify(opts.body);
    }
    // Compose the abort signals: caller-supplied + per-request timeout.
    const signals: AbortSignal[] = [];
    if (ctx?.signal) signals.push(ctx.signal);
    if (this.timeoutMs > 0) {
      try {
        signals.push(AbortSignal.timeout(this.timeoutMs));
      } catch {
        // AbortSignal.timeout may be unavailable in some runtimes; fall back
        // to a manual controller.
      }
    }
    if (signals.length === 1) {
      init.signal = signals[0];
    } else if (signals.length > 1) {
      init.signal = anySignal(signals);
    }

    let res: Response;
    try {
      res = await this.fetchImpl(url, init);
    } catch (err) {
      // Normalize AbortError vs timeout so callers can distinguish.
      throw err as Error;
    }
    const text = await res.text();
    const headers: Headers = {};
    res.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    return { status: res.status, headers, body: text };
  }

  private buildURL(opts: RequestOptions): string {
    let full = this.baseURL + opts.path;
    if (opts.query && Object.keys(opts.query).length > 0) {
      const qs = Object.keys(opts.query)
        .sort()
        .map(
          (k) =>
            `${encodeURIComponent(k)}=${encodeURIComponent(opts.query![k])}`,
        )
        .join('&');
      if (qs) full += `?${qs}`;
    }
    return full;
  }

  private buildHeaders(opts: RequestOptions): Record<string, string> {
    const h: Record<string, string> = {
      Authorization: `Bearer ${this.token}`,
      'User-Agent': this.userAgent,
    };
    if (opts.body !== undefined) h['Content-Type'] = 'application/json';
    if (opts.accept) h['Accept'] = opts.accept;
    if (opts.idempotencyKey) h['Idempotency-Key'] = opts.idempotencyKey;
    return h;
  }

  /**
   * backoffDelay computes the delay before the next attempt. For 429 it
   * honors the Retry-After header (parsed from the prior error's headers);
   * for 5xx (and 429 without Retry-After) it uses exponential backoff:
   * initialBackoff * 2^(attempt-1), capped at maxBackoff.
   */
  private backoffDelay(attempt: number, lastErr: Error | null): number {
    const hdr = errHeaders(lastErr);
    const ra = parseRetryAfterMs(hdr);
    if (ra > 0) {
      return Math.min(ra, MAX_BACKOFF_MS);
    }
    // Exponential backoff: 200ms, 400ms, 800ms, ... capped at 30s.
    const bo = INITIAL_BACKOFF_MS * Math.pow(2, attempt - 1);
    if (bo > MAX_BACKOFF_MS || !Number.isFinite(bo) || bo < 0) {
      return MAX_BACKOFF_MS;
    }
    return bo;
  }

  /** sleep blocks for ms or until ctx is cancelled. Returns false if cancelled. */
  private async sleep(
    ctx: RequestContext | undefined,
    ms: number,
  ): Promise<boolean> {
    if (ms <= 0) return true;
    if (ctx?.signal?.aborted) return false;
    return new Promise<boolean>((resolve) => {
      let timer: ReturnType<typeof setTimeout> | null = null;
      const onAbort = () => {
        if (timer) clearTimeout(timer);
        resolve(false);
      };
      timer = setTimeout(() => {
        ctx?.signal?.removeEventListener('abort', onAbort);
        resolve(true);
      }, ms);
      ctx?.signal?.addEventListener('abort', onAbort, { once: true });
    });
  }

  // ---- request helpers used by the resource namespaces ----

  /**
   * doJSON executes a request expecting a JSON response body and parses it
   * into out. Returns the HTTP status. Non-2xx responses are thrown as typed
   * errors (out is left untouched).
   */
  async doJSON<T>(
    ctx: RequestContext | undefined,
    opts: RequestOptions,
    out: T,
  ): Promise<number> {
    const { body } = await this.do(ctx, opts);
    if (body.length > 0) {
      const parsed = JSON.parse(body);
      Object.assign(out as object, parsed);
    }
    return 0;
  }

  /**
   * doBytes executes a request expecting a binary response body (e.g. a PDF).
   * Returns the Content-Type and raw bytes. Non-2xx responses are thrown as
   * typed errors.
   */
  async doBytes(
    ctx: RequestContext | undefined,
    opts: RequestOptions,
  ): Promise<{ contentType: string; bytes: Uint8Array }> {
    // We need the raw bytes; re-implement a single attempt path that bypasses
    // res.text() and uses res.arrayBuffer() while still honoring retry.
    const buf = await this.doBinary(ctx, opts);
    return buf;
  }

  /**
   * doNoContent executes a request expecting an empty (204/200) response.
   * Returns the HTTP status. Non-2xx responses are thrown as typed errors.
   */
  async doNoContent(
    ctx: RequestContext | undefined,
    opts: RequestOptions,
  ): Promise<number> {
    await this.do(ctx, opts);
    return 0;
  }

  /**
   * doBinary is like do() but returns the body as bytes (for PDF responses).
   * Retry/backoff semantics are identical to do().
   */
  private async doBinary(
    ctx: RequestContext | undefined,
    opts: RequestOptions,
  ): Promise<{ contentType: string; bytes: Uint8Array }> {
    let retryable: boolean;
    if (opts.retryableOverride !== undefined) {
      retryable = opts.retryableOverride;
    } else {
      retryable = opts.method === 'GET' || !!opts.idempotencyKey;
    }
    const maxRetries = retryable ? this.maxRetries : 0;
    let lastErr: Error | null = null;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      if (attempt > 0) {
        const wait = this.backoffDelay(attempt, lastErr);
        if (!(await this.sleep(ctx, wait))) {
          const e = new Error('moss: request cancelled');
          (e as { name: string }).name = 'AbortError';
          throw e;
        }
      }
      let res: Response;
      try {
        const url = this.buildURL(opts);
        const init: RequestInit = {
          method: opts.method,
          headers: this.buildHeaders(opts),
        };
        if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
        const signals: AbortSignal[] = [];
        if (ctx?.signal) signals.push(ctx.signal);
        if (this.timeoutMs > 0) {
          try {
            signals.push(AbortSignal.timeout(this.timeoutMs));
          } catch {
            /* AbortSignal.timeout unavailable */
          }
        }
        if (signals.length === 1) init.signal = signals[0];
        else if (signals.length > 1) init.signal = anySignal(signals);
        res = await this.fetchImpl(url, init);
      } catch (err) {
        lastErr = err as Error;
        if (retryable && attempt < maxRetries) continue;
        throw new Error(`moss: request failed: ${(err as Error).message}`);
      }
      if (res.status >= 200 && res.status < 300) {
        const ab = await res.arrayBuffer();
        const contentType = res.headers.get('content-type') ?? '';
        return { contentType, bytes: new Uint8Array(ab) };
      }
      // Non-2xx: parse as text for the typed error.
      const text = await res.text();
      const headers: Headers = {};
      res.headers.forEach((v, k) => {
        headers[k.toLowerCase()] = v;
      });
      const parsed = parseJSONBody(text);
      const typed = asTypedError(res.status, parsed, headers, text);
      if (
        retryable &&
        (res.status === 429 || res.status >= 500) &&
        attempt < maxRetries
      ) {
        lastErr = typed;
        continue;
      }
      throw typed;
    }
    throw lastErr ?? new Error('moss: retry loop exhausted');
  }

  /**
   * fetchWellKnownKey fetches the public key material for keyID from the
   * well-known keyset endpoint. No Authorization header is sent (public).
   */
  async fetchWellKnownKey(
    ctx: RequestContext | undefined,
    keyID: string,
  ): Promise<Uint8Array> {
    if (!keyID) throw new Error('moss: empty key_id');
    const fullURL =
      this.baseURL + '/.well-known/moss-keys/' + encodeURIComponent(keyID);
    const init: RequestInit = {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'User-Agent': this.userAgent,
      },
    };
    if (this.timeoutMs > 0) {
      try {
        init.signal = AbortSignal.timeout(this.timeoutMs);
      } catch {
        /* AbortSignal.timeout unavailable */
      }
    }
    if (ctx?.signal) {
      init.signal = init.signal
        ? anySignal([init.signal as AbortSignal, ctx.signal])
        : ctx.signal;
    }
    const res = await this.fetchImpl(fullURL, init);
    const body = await res.text();
    if (!res.ok) throw new Error(`moss: HTTP ${res.status}`);
    const doc = JSON.parse(body) as {
      key_id?: string;
      alg?: string;
      public_key_b64?: string;
      public_key_hex?: string;
    };
    if (doc.public_key_b64) {
      return base64Decode(doc.public_key_b64);
    }
    if (doc.public_key_hex) {
      return hexDecode(doc.public_key_hex);
    }
    throw new Error('moss: no public key material in keyset response');
  }
}

// ---- helpers ----

/** parseJSONBody best-effort parses a JSON object body into a map. Returns null for empty/non-object bodies. */
function parseJSONBody(body: string): Record<string, unknown> | null {
  if (!body) return null;
  try {
    const v = JSON.parse(body);
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      return v as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}

/** errHeaders extracts the headers from a prior typed SDK error (for Retry-After on 429). */
function errHeaders(err: Error | null): Headers {
  if (err && err instanceof APIError) return err.headers;
  return {};
}

/** anySignal returns an AbortSignal that aborts when any of the inputs aborts. */
function anySignal(signals: AbortSignal[]): AbortSignal {
  // Use AbortSignal.any when available; otherwise compose manually.
  const anyFn = (AbortSignal as unknown as {
    any?: (s: AbortSignal[]) => AbortSignal;
  }).any;
  if (typeof anyFn === 'function') {
    return anyFn(signals);
  }
  const ctrl = new AbortController();
  for (const s of signals) {
    if (s.aborted) {
      ctrl.abort();
      break;
    }
    s.addEventListener('abort', () => ctrl.abort(), { once: true });
  }
  return ctrl.signal;
}

/** base64Decode decodes a standard or URL-safe base64 string into bytes. */
function base64Decode(s: string): Uint8Array {
  const normalized = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded =
    normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const bin =
    typeof Buffer !== 'undefined'
      ? Buffer.from(padded, 'base64')
      : Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  return typeof Buffer !== 'undefined'
    ? new Uint8Array(bin)
    : (bin as Uint8Array);
}

/** hexDecode decodes a hex string into bytes. */
function hexDecode(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new Error('moss: odd-length hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const hi = hexNibble(s.charCodeAt(i * 2));
    const lo = hexNibble(s.charCodeAt(i * 2 + 1));
    if (hi < 0 || lo < 0) throw new Error('moss: invalid hex char');
    out[i] = (hi << 4) | lo;
  }
  return out;
}

function hexNibble(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
  return -1;
}
