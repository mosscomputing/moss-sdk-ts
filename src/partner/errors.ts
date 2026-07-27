/**
 * MOSS Partner SDK — typed error hierarchy (parity with moss-go/partner).
 *
 * HTTP-status → class mapping (identical across TS/Python/Go):
 *   401/403 → AuthError
 *   404     → NotFoundError
 *   409     → ConflictError
 *   429     → RateLimitError (carries retryAfter)
 *   400/422 → ValidationError
 *   5xx     → ServerError
 *
 * Every typed class extends APIError so `instanceof APIError` and the
 * instanceof check for the specific class both succeed. APIError exposes the
 * backend error-code string (`code`), the HTTP `status`, the human-readable
 * `message`, the opaque `requestId`, the response `headers`, and the parsed
 * JSON `body`.
 */

/** Response HTTP headers (a plain string→string record). */
export type Headers = Record<string, string>;

/** Parsed JSON response body (a generic object). */
export type Body = Record<string, unknown> | null;

/**
 * APIError is the common error type carried by every typed SDK error. The
 * typed classes extend it so `err instanceof APIError` and
 * `err instanceof NotFoundError` both succeed.
 */
export class APIError extends Error {
  /** HTTP status code returned by the backend. */
  readonly status: number;
  /** Backend error-code string (e.g. "customer_not_found", "invalid_transition"). */
  readonly code: string;
  /** Human-readable error message. */
  readonly message: string;
  /** Opaque backend request id (echoed from the "request_id" field when present). */
  readonly requestId: string;
  /** Response HTTP headers (used by RateLimitError to read Retry-After). */
  readonly headers: Headers;
  /** Parsed JSON response body (null for non-JSON bodies). */
  readonly body: Body;
  /** Raw response body bytes (as a string). Always populated. */
  readonly rawBody: string;

  constructor(opts: {
    status: number;
    code: string;
    message: string;
    requestId?: string;
    headers?: Headers;
    body?: Body;
    rawBody?: string;
  }) {
    super(
      opts.code
        ? `moss: ${opts.code} (status ${opts.status}): ${opts.message}`
        : `moss: status ${opts.status}: ${opts.message}`,
    );
    this.name = 'APIError';
    this.status = opts.status;
    this.code = opts.code;
    this.message = opts.message;
    this.requestId = opts.requestId ?? '';
    this.headers = opts.headers ?? {};
    this.body = opts.body ?? null;
    this.rawBody = opts.rawBody ?? '';
  }

  /** Returns a top-level field from the parsed error body, or undefined. */
  field(key: string): unknown {
    return this.body?.[key];
  }

  /** Returns the raw response body as a string. */
  raw(): string {
    return this.rawBody;
  }
}

/** AuthError — raised for HTTP 401/403 (missing/invalid/wrong-prefix token). */
export class AuthError extends APIError {
  constructor(opts: ConstructorParameters<typeof APIError>[0]) {
    super(opts);
    this.name = 'AuthError';
  }
}

/** NotFoundError — raised for HTTP 404 (existence-non-leak convention). */
export class NotFoundError extends APIError {
  constructor(opts: ConstructorParameters<typeof APIError>[0]) {
    super(opts);
    this.name = 'NotFoundError';
  }
}

/** ConflictError — raised for HTTP 409 (invalid lifecycle transition, idempotency-key conflict, delegation depth/escalation). */
export class ConflictError extends APIError {
  constructor(opts: ConstructorParameters<typeof APIError>[0]) {
    super(opts);
    this.name = 'ConflictError';
  }
}

/**
 * RateLimitError — raised for HTTP 429. Carries the Retry-After value parsed
 * from the response header (seconds or HTTP-date). retryAfter is 0 when the
 * header is absent (the backend does not always send Retry-After).
 */
export class RateLimitError extends APIError {
  /** Parsed Retry-After duration in milliseconds. 0 if absent/unparseable. */
  readonly retryAfterMs: number;
  constructor(
    opts: ConstructorParameters<typeof APIError>[0],
    retryAfterMs: number,
  ) {
    super(opts);
    this.name = 'RateLimitError';
    this.retryAfterMs = retryAfterMs;
  }
}

/** ValidationError — raised for HTTP 400/422 (request validation failure). */
export class ValidationError extends APIError {
  constructor(opts: ConstructorParameters<typeof APIError>[0]) {
    super(opts);
    this.name = 'ValidationError';
  }
}

/** ServerError — raised for HTTP 5xx. */
export class ServerError extends APIError {
  constructor(opts: ConstructorParameters<typeof APIError>[0]) {
    super(opts);
    this.name = 'ServerError';
  }
}

/**
 * asTypedError maps an HTTP status + parsed body to the canonical typed error.
 * @param status HTTP status code
 * @param body parsed JSON body (may be null)
 * @param headers response headers (read for Retry-After on 429)
 * @param raw raw response body string
 */
export function asTypedError(
  status: number,
  body: Body,
  headers: Headers,
  raw: string,
): Error {
  const api = buildAPIError(status, body, headers, raw);
  switch (true) {
    case status === 429:
      return new RateLimitError(
        {
          status: api.status,
          code: api.code,
          message: api.message,
          requestId: api.requestId,
          headers: api.headers,
          body: api.body,
          rawBody: api.rawBody,
        },
        parseRetryAfterMs(headers),
      );
    case status === 404:
      return new NotFoundError({
        status: api.status,
        code: api.code,
        message: api.message,
        requestId: api.requestId,
        headers: api.headers,
        body: api.body,
        rawBody: api.rawBody,
      });
    case status === 401 || status === 403:
      return new AuthError({
        status: api.status,
        code: api.code,
        message: api.message,
        requestId: api.requestId,
        headers: api.headers,
        body: api.body,
        rawBody: api.rawBody,
      });
    case status === 409:
      return new ConflictError({
        status: api.status,
        code: api.code,
        message: api.message,
        requestId: api.requestId,
        headers: api.headers,
        body: api.body,
        rawBody: api.rawBody,
      });
    case status === 400 || status === 422:
      return new ValidationError({
        status: api.status,
        code: api.code,
        message: api.message,
        requestId: api.requestId,
        headers: api.headers,
        body: api.body,
        rawBody: api.rawBody,
      });
    case status >= 500:
      return new ServerError({
        status: api.status,
        code: api.code,
        message: api.message,
        requestId: api.requestId,
        headers: api.headers,
        body: api.body,
        rawBody: api.rawBody,
      });
    default:
      return api;
  }
}

/** buildAPIError constructs the base APIError fields from a response. */
export function buildAPIError(
  status: number,
  body: Body,
  headers: Headers,
  raw: string,
): APIError {
  let code = '';
  let message = '';
  let requestId = '';
  if (body) {
    const errStr = body['error'];
    if (typeof errStr === 'string') code = errStr;
    if (!code) {
      const codeStr = body['code'];
      if (typeof codeStr === 'string') code = codeStr;
    }
    const msgStr = body['message'];
    if (typeof msgStr === 'string') message = msgStr;
    const ridStr = body['request_id'];
    if (typeof ridStr === 'string') requestId = ridStr;
  }
  if (!code && status === 404) {
    // Uniform 404 handler rewrites the body to {"error":"not_found",...};
    // the route-level code is lost. Surface "not_found" as the canonical
    // code for any 404 without an explicit error field.
    code = 'not_found';
  }
  if (!message) message = `HTTP ${status}`;
  return new APIError({
    status,
    code,
    message,
    requestId,
    headers,
    body,
    rawBody: raw,
  });
}

/**
 * parseRetryAfterMs parses the Retry-After response header per RFC 7231.
 * Accepts either a delta-seconds value or an HTTP-date. Returns 0 if the
 * header is absent or unparseable.
 */
export function parseRetryAfterMs(headers: Headers): number {
  const v = headers['retry-after'] ?? headers['Retry-After'];
  if (!v) return 0;
  // Delta-seconds (most common).
  const secs = Number.parseInt(v, 10);
  if (Number.isFinite(secs) && secs >= 0 && String(secs) === v.trim()) {
    return secs * 1000;
  }
  // HTTP-date (RFC 7231 §7.1.3).
  const t = Date.parse(v);
  if (Number.isFinite(t)) {
    const d = t - Date.now();
    return d > 0 ? d : 0;
  }
  return 0;
}

// ---- predicate helpers (parity with Go's IsAuth/IsNotFound/...) ----

export function isAuth(err: unknown): err is AuthError {
  return err instanceof AuthError;
}
export function isNotFound(err: unknown): err is NotFoundError {
  return err instanceof NotFoundError;
}
export function isRateLimit(err: unknown): err is RateLimitError {
  return err instanceof RateLimitError;
}
export function isValidation(err: unknown): err is ValidationError {
  return err instanceof ValidationError;
}
export function isConflict(err: unknown): err is ConflictError {
  return err instanceof ConflictError;
}
export function isServer(err: unknown): err is ServerError {
  return err instanceof ServerError;
}

/** Returns the backend error-code string from err, or '' if not an SDK error. */
export function codeOf(err: unknown): string {
  return err instanceof APIError ? err.code : '';
}

/** Returns the HTTP status from err, or 0 if not an SDK error. */
export function statusOf(err: unknown): number {
  return err instanceof APIError ? err.status : 0;
}

/**
 * currentStatus extracts the current_status field echoed in a 409
 * invalid_transition body, or '' if absent. Convenience for callers handling
 * lifecycle conflict errors.
 */
export function currentStatus(err: unknown): string {
  if (!(err instanceof APIError) || !err.body) return '';
  const v = err.body['current_status'];
  return typeof v === 'string' ? v : '';
}
