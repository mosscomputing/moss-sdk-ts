/**
 * MOSS Partner SDK — TypeScript surface (parity with moss-go/partner).
 *
 * A Client is constructed with a partner (prt_), customer (cust_), or
 * capability (cap_) token. The persona is inferred from the token prefix.
 * The default base URL is http://localhost:3100 (overridable).
 *
 * Partner persona (prt_) exposes the customers.* resource namespace:
 *
 *   import { newPartnerClient } from '@moss/sdk/partner';
 *   const client = newPartnerClient({ token: process.env.MOSS_PRT_TOKEN });
 *   const cust = await client.customers.create(undefined, {
 *     external_id: 'ext-1', name: 'Acme',
 *   }, 'idem-key-1');
 *   console.log(cust.customer_id, cust.status);
 *
 * Resource namespaces:
 *   - customers: create / get / list / update / deactivate / promote /
 *     suspend / reactivate / session / asCustomer / revokeSession /
 *     complianceReport
 *   - compliance: verifyReport (offline ML-DSA-44 signature verification)
 *
 * Client-side helpers (no network validation):
 *   - portalUrl: signed white-label deep-link construction (tamper-evident)
 *
 * Typed error hierarchy (parity contract — identical HTTP-status→class
 * mapping across TS/Python/Go):
 *   - 401/403 → AuthError
 *   - 404     → NotFoundError
 *   - 409     → ConflictError
 *   - 429     → RateLimitError (carries retryAfterMs)
 *   - 400/422 → ValidationError
 *   - 5xx     → ServerError
 */

import { Client } from './client.js';
import type { Config } from './client.js';
import { CustomersService } from './customers.js';
import { ComplianceService } from './compliance.js';

// Re-export the public surface.
export {
  // client / config (values)
  Client,
  DEFAULT_BASE_URL,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_MAX_RETRIES,
  INITIAL_BACKOFF_MS,
  MAX_BACKOFF_MS,
  PREFIX_PARTNER,
  PREFIX_CUSTOMER,
  PREFIX_CAPABILITY,
  inferPersona,
} from './client.js';
export type { Config, Persona, RequestContext } from './client.js';

export {
  // errors (values)
  APIError,
  AuthError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  ValidationError,
  ServerError,
  asTypedError,
  buildAPIError,
  parseRetryAfterMs,
  isAuth,
  isNotFound,
  isRateLimit,
  isValidation,
  isConflict,
  isServer,
  codeOf,
  statusOf,
  currentStatus,
} from './errors.js';
export type { Headers, Body } from './errors.js';

export {
  // customers (values)
  CustomersService,
  STATUS_PENDING,
  STATUS_SANDBOX_ACTIVE,
  STATUS_PRODUCTION_ACTIVE,
  STATUS_SUSPENDED,
  STATUS_DEACTIVATED,
} from './customers.js';
export type {
  CustomerStatus,
  CreateCustomerRequest,
  UpdateCustomerRequest,
  PromoteAttestation,
  PromoteBilling,
  PromoteCustomerRequest,
  SuspendCustomerRequest,
  ReactivateResolution,
  ReactivateCustomerRequest,
  ListCustomersOptions,
  CustomerListResponse,
  Customer,
  Governance,
  Limits,
  CustomerToken,
  CustomerCredentials,
  SessionMint,
  SessionOpts,
  SessionResult,
} from './customers.js';

export {
  // compliance (values)
  ComplianceService,
  ComplianceReport,
} from './compliance.js';
export type { VerifyResult } from './compliance.js';

export {
  // portalUrl (values)
  portalUrl,
  portalVerifySignature,
  DEFAULT_PORTAL_BASE_URL,
} from './portalurl.js';
export type { PortalURLOpts } from './portalurl.js';

/**
 * newPartnerClient constructs a Partner SDK Client and wires its resource
 * namespaces (customers, compliance). Convenience wrapper around
 * `new Client(cfg)` so callers do not need to wire namespaces manually.
 */
export function newPartnerClient(cfg: Config): Client {
  const c = new Client(cfg);
  c.customers = new CustomersService(c);
  c.compliance = new ComplianceService(c);
  return c;
}
