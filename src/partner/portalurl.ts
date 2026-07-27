/**
 * MOSS Partner SDK — portalUrl() signed white-label deep-link helper (parity
 * with moss-go/partner/portalurl.go).
 *
 * Constructs a signed white-label deep-link from the portal base + the scoped
 * cust_ token + theme params. The link is tamper-evident: the query string
 * carries an HMAC-SHA256 signature over the canonical parameter set, keyed
 * by a key derived from the token. The portal validates the signature on
 * receipt (Stripe-Checkout pattern). No network call is made — construction
 * is purely client-side, and an expired/invalid token still constructs a URL
 * (validation is the portal's job).
 *
 * The URL shape is:
 *
 *   <portalBase>/portal/customer/<customerID>?t=<token>&theme[...]=...&exp=<unix>&sig=<base64url-hmac>
 *
 * The signature covers the canonical sorted key=value pair string of all
 * query params except `sig`, HMAC-SHA256 keyed by sha256(token).
 *
 * The canonical pair string and URL encoding match Go's `url.QueryEscape`
 * exactly (spaces → "+", unreserved = A-Za-z0-9-_.~), so the same inputs
 * produce byte-identical URLs across TS/Python/Go (parity contract).
 */

import { createHmac, createHash } from 'node:crypto';

/** Default white-label portal base URL. */
export const DEFAULT_PORTAL_BASE_URL = 'https://dev-console.mosscomputing.com';

/** PortalURLOpts controls PortalURL construction. */
export interface PortalURLOpts {
  /** White-label portal base URL. Defaults to DEFAULT_PORTAL_BASE_URL. */
  portalBase?: string;
  /** Scoped cust_ token to embed in the deep-link. Required. */
  token: string;
  /** Optional branding/theme params (e.g. { primary: "#fff", mode: "dark" }). */
  theme?: Record<string, string>;
  /** Optional deep-link expiry (Date). Covered by the signature. */
  expires?: Date;
}

/**
 * portalUrl constructs a signed white-label deep-link. No network call.
 * Throws if customerID or token is empty.
 */
export function portalUrl(
  customerID: string,
  opts: PortalURLOpts,
): string {
  if (!customerID) throw new Error('moss: portalUrl: customer_id is required');
  if (!opts.token) throw new Error('moss: portalUrl: token is required');
  let base = opts.portalBase ?? DEFAULT_PORTAL_BASE_URL;
  base = base.replace(/\/+$/, '');

  // Build params as a multi-map (key → list of values). We always set single
  // values per key here, but the canonical signing iterates in sorted-key
  // order so the output is deterministic across runs.
  const params: Array<[string, string]> = [];
  params.push(['t', opts.token]);
  if (opts.theme) {
    for (const [k, v] of Object.entries(opts.theme)) {
      params.push([`theme.${k}`, v]);
    }
  }
  if (opts.expires) {
    params.push(['exp', String(Math.floor(opts.expires.getTime() / 1000))]);
  }

  const sig = portalSign(opts.token, params);
  params.push(['sig', sig]);

  // Final URL query string is sorted by key (parity with Go's portalEncode),
  // including the `sig` param, so the URL is byte-identical across TS/Go for
  // the same inputs.
  const sorted = [...params].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  const qs = sorted
    .map(([k, v]) => `${queryEscape(k)}=${queryEscape(v)}`)
    .join('&');
  return `${base}/portal/customer/${pathEscape(customerID)}?${qs}`;
}

/**
 * portalSign computes the HMAC-SHA256 signature over the canonical sorted
 * key=value pair string of all params (excluding `sig`), keyed by
 * sha256(token). The signature is base64url-encoded (no padding).
 */
function portalSign(token: string, params: Array<[string, string]>): string {
  const key = createHash('sha256').update(token).digest();
  const pairs = canonicalPairs(params);
  const mac = createHmac('sha256', key).update(pairs).digest();
  return mac.toString('base64url');
}

/**
 * portalVerifySignature verifies a portalUrl signature client-side. Returns
 * true iff the `sig` query param matches the HMAC-SHA256 over the canonical
 * pair string of all other params, keyed by sha256(token). Pure client-side
 * check (no network) used by the portal to detect tampering before the BFF
 * introspection call.
 */
export function portalVerifySignature(rawURL: string): boolean {
  let u: URL;
  try {
    u = new URL(rawURL);
  } catch {
    return false;
  }
  const sp = u.searchParams;
  const sig = sp.get('sig');
  if (!sig) return false;
  const token = sp.get('t');
  if (!token) return false;
  // Reconstruct the params list (excluding sig) from the URL's search params.
  const params: Array<[string, string]> = [];
  sp.forEach((v, k) => {
    if (k !== 'sig') params.push([k, v]);
  });
  const want = portalSign(token, params);
  // Constant-time compare.
  return safeEqual(sig, want);
}

/**
 * canonicalPairs returns the canonical "k=v&k2=v2..." string of params
 * (sorted by key, URL-encoded values via Go-compatible queryEscape),
 * excluding the `sig` key. Byte-identical for the same inputs across
 * TS/Python/Go.
 */
function canonicalPairs(params: Array<[string, string]>): string {
  // Sort by key; for equal keys, preserve insertion order (stable).
  const indexed = params.map(([k, v], i) => ({ k, v, i }));
  indexed.sort((a, b) =>
    a.k < b.k ? -1 : a.k > b.k ? 1 : a.i - b.i,
  );
  const parts: string[] = [];
  for (const { k, v } of indexed) {
    parts.push(`${queryEscape(k)}=${queryEscape(v)}`);
  }
  return parts.join('&');
}

/**
 * queryEscape mirrors Go's `url.QueryEscape`:
 *   - unreserved (A-Za-z0-9-_.~) is kept
 *   - space → "+"
 *   - everything else → "%XX" (uppercase hex)
 * This produces output byte-identical to Go for the same input (parity).
 */
function queryEscape(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (
      (c >= 0x41 && c <= 0x5a) || // A-Z
      (c >= 0x61 && c <= 0x7a) || // a-z
      (c >= 0x30 && c <= 0x39) || // 0-9
      c === 0x2d || // -
      c === 0x5f || // _
      c === 0x2e || // .
      c === 0x7e // ~
    ) {
      out += s[i];
    } else if (c === 0x20) {
      // space → "+"
      out += '+';
    } else {
      // UTF-8 encode the code point, then percent-encode each byte.
      const bytes = new TextEncoder().encode(s[i]);
      for (const b of bytes) {
        out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
      }
    }
  }
  return out;
}

/**
 * pathEscape mirrors Go's `url.PathEscape` for a single path segment. Kept
 * chars: A-Za-z0-9 - _ . ~ ! $ & ' ( ) * + , ; = : @. Everything else →
 * "%XX" (uppercase hex). For UUID/slug customer IDs this matches
 * encodeURIComponent for the common case; the explicit allow-list keeps
 * parity with Go for edge-case characters.
 */
function pathEscape(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (
      (c >= 0x41 && c <= 0x5a) ||
      (c >= 0x61 && c <= 0x7a) ||
      (c >= 0x30 && c <= 0x39) ||
      c === 0x2d || // -
      c === 0x5f || // _
      c === 0x2e || // .
      c === 0x7e || // ~
      c === 0x21 || // !
      c === 0x24 || // $
      c === 0x26 || // &
      c === 0x27 || // '
      c === 0x28 || // (
      c === 0x29 || // )
      c === 0x2a || // *
      c === 0x2b || // +
      c === 0x2c || // ,
      c === 0x3b || // ;
      c === 0x3d || // =
      c === 0x3a || // :
      c === 0x40 // @
    ) {
      out += s[i];
    } else {
      const bytes = new TextEncoder().encode(s[i]);
      for (const b of bytes) {
        out += '%' + b.toString(16).toUpperCase().padStart(2, '0');
      }
    }
  }
  return out;
}

/** safeEqual is a constant-time string compare. */
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
