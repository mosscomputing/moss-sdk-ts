/**
 * MOSS Partner SDK — customers.* resource namespace (parity with
 * moss-go/partner/customers.go + session.go + compliance.go).
 *
 * customers.create/get/list/update/deactivate + lifecycle
 * promote/suspend/reactivate + session()/asCustomer()/revokeSession() +
 * complianceReport(). Idempotency-Key passthrough on create/session/promote.
 */

import { Client, RequestContext } from './client.js';
import { currentStatus as currentStatusFn, isConflict } from './errors.js';
import {
  ComplianceReport as ComplianceReportResult,
  ComplianceService,
} from './compliance.js';

// ---- status enum (canonical string values — parity contract) ----

export type CustomerStatus =
  | 'pending'
  | 'sandbox_active'
  | 'production_active'
  | 'suspended'
  | 'deactivated';

export const STATUS_PENDING: CustomerStatus = 'pending';
export const STATUS_SANDBOX_ACTIVE: CustomerStatus = 'sandbox_active';
export const STATUS_PRODUCTION_ACTIVE: CustomerStatus = 'production_active';
export const STATUS_SUSPENDED: CustomerStatus = 'suspended';
export const STATUS_DEACTIVATED: CustomerStatus = 'deactivated';

// ---- customer shapes ----

export interface Governance {
  frameworks_active: string[];
  policies_inherited: number;
  /** null when not yet scored. */
  compliance_score: number | null;
}

export interface Limits {
  agents: number;
  capability_tokens_per_hour: number;
  webhooks?: number;
  envelopes_per_month?: number;
}

export interface CustomerToken {
  /** Raw cust_ token (returned once; never logged/persisted). */
  token: string;
  prefix: string;
}

export interface CustomerCredentials {
  customer_token: CustomerToken;
}

export interface Customer {
  customer_id: string;
  external_id?: string;
  name: string;
  status: CustomerStatus;
  partner_id?: string;
  tier?: string;
  created_at?: string;
  updated_at?: string;
  governance?: Governance;
  limits?: Limits;
  settings?: Record<string, unknown>;
  /** Populated ONLY on Create (one-time raw cust_ token). */
  credentials?: CustomerCredentials;
}

// ---- request bodies ----

export interface CreateCustomerRequest {
  external_id: string;
  name: string;
  settings?: Record<string, unknown>;
}

export interface UpdateCustomerRequest {
  limits?: Record<string, unknown>;
  settings?: Record<string, unknown>;
}

export interface PromoteAttestation {
  kyc_completed: boolean;
  kyc_provider?: string;
  kyc_verification_id?: string;
  terms_accepted: boolean;
  terms_version?: string;
  terms_accepted_by?: string;
  terms_accepted_at?: string;
  compliance_reviewed: boolean;
  compliance_reviewer?: string;
  compliance_notes?: string;
}

export interface PromoteBilling {
  tier?: string;
  billing_email?: string;
  payment_method?: string;
  billing_cycle?: string;
}

export interface PromoteCustomerRequest {
  attestation: PromoteAttestation;
  billing: PromoteBilling;
  governance_upgrade?: Record<string, unknown>;
}

export interface SuspendCustomerRequest {
  reason: string;
  suspend_agents_immediately?: boolean;
  grace_period_days?: number;
  notification_email?: string;
}

export interface ReactivateResolution {
  issue_resolved: boolean;
  details?: string;
}

export interface ReactivateCustomerRequest {
  resolution?: ReactivateResolution;
}

export interface ListCustomersOptions {
  /** Page size (default 20, max 100 on the backend). */
  limit?: number;
  /** Opaque pagination cursor from a prior response. */
  cursor?: string;
}

export interface CustomerListResponse {
  customers: Customer[];
  next_cursor?: string;
}

// ---- session shapes ----

export interface SessionMint {
  session_id: string;
  customer_id: string;
  /** Raw cust_ session token (returned once; never logged/persisted). */
  token: string;
  prefix: string;
  expires_at: string;
}

export interface SessionOpts {
  /** Partner-scoped idempotency key (optional but recommended for safe retry). */
  idempotencyKey?: string;
}

export interface SessionResult {
  mint: SessionMint;
  client: Client;
}

// ---- service ----

/**
 * CustomersService is the customers.* resource namespace (partner persona).
 */
export class CustomersService {
  private readonly c: Client;

  constructor(c: Client) {
    this.c = c;
  }

  /**
   * Create creates a customer (organization) under the calling partner. The
   * Idempotency-Key is partner-scoped: a same-key/same-body replay returns
   * the same customer + cust_ token; a same-key/different-body replay is a
   * 409 idempotency_key_conflict. The raw cust_ token is returned exactly
   * once in cust.credentials.customer_token.token.
   */
  async create(
    ctx: RequestContext | undefined,
    req: CreateCustomerRequest,
    idempotencyKey?: string,
  ): Promise<Customer> {
    const guard = this.c.requirePartner('customers.create');
    if (guard) throw guard;
    if (!req) throw new Error('moss: customers.create: request is required');
    if (!req.external_id || !req.name) {
      throw new Error(
        'moss: customers.create: external_id and name are required',
      );
    }
    const out: Customer = {} as Customer;
    await this.c.doJSON(
      ctx,
      {
        method: 'POST',
        path: '/v1/partner/customers',
        body: req,
        idempotencyKey,
      },
      out,
    );
    return out;
  }

  /**
   * Get returns the customer with the given id, including governance/limits
   * summary. A foreign or unknown id returns NotFoundError (404, existence-
   * non-leak convention — never 403).
   */
  async get(
    ctx: RequestContext | undefined,
    customerID: string,
  ): Promise<Customer> {
    const guard = this.c.requirePartner('customers.get');
    if (guard) throw guard;
    if (!customerID) throw new Error('moss: customers.get: customer_id is required');
    const out: Customer = {} as Customer;
    await this.c.doJSON(
      ctx,
      {
        method: 'GET',
        path: '/v1/partner/customers/' + encodeURIComponent(customerID),
      },
      out,
    );
    return out;
  }

  /**
   * List returns a page of customers owned by the calling partner. Each entry
   * carries a status field with a value in the canonical status enum. Pass
   * opts.cursor from the response's next_cursor to fetch the next page.
   */
  async list(
    ctx: RequestContext | undefined,
    opts?: ListCustomersOptions,
  ): Promise<CustomerListResponse> {
    const guard = this.c.requirePartner('customers.list');
    if (guard) throw guard;
    const query: Record<string, string> = {};
    if (opts?.limit && opts.limit > 0) query.limit = String(opts.limit);
    if (opts?.cursor) query.cursor = opts.cursor;
    const out: CustomerListResponse = { customers: [] };
    await this.c.doJSON(
      ctx,
      { method: 'GET', path: '/v1/partner/customers', query },
      out,
    );
    if (!out.customers) out.customers = [];
    return out;
  }

  /**
   * Update applies a partial update (limits/settings merge) to a customer. A
   * subsequent get reflects the updated values.
   */
  async update(
    ctx: RequestContext | undefined,
    customerID: string,
    req: UpdateCustomerRequest,
  ): Promise<Customer> {
    const guard = this.c.requirePartner('customers.update');
    if (guard) throw guard;
    if (!customerID) throw new Error('moss: customers.update: customer_id is required');
    if (!req) throw new Error('moss: customers.update: request is required');
    const out: Customer = {} as Customer;
    await this.c.doJSON(
      ctx,
      {
        method: 'PATCH',
        path: '/v1/partner/customers/' + encodeURIComponent(customerID),
        body: req,
      },
      out,
    );
    return out;
  }

  /**
   * Deactivate soft-deactivates a customer. The record remains retrievable
   * via get with status == "deactivated" (not a hard delete).
   */
  async deactivate(
    ctx: RequestContext | undefined,
    customerID: string,
  ): Promise<Customer> {
    const guard = this.c.requirePartner('customers.deactivate');
    if (guard) throw guard;
    if (!customerID) throw new Error('moss: customers.deactivate: customer_id is required');
    const out: Customer = {} as Customer;
    await this.c.doJSON(
      ctx,
      {
        method: 'DELETE',
        path: '/v1/partner/customers/' + encodeURIComponent(customerID),
      },
      out,
    );
    return out;
  }

  /**
   * Promote promotes a sandbox_active customer to production_active. Requires
   * a complete attestation + billing bundle. An invalid from-state returns
   * ConflictError (409, code "invalid_transition") with current_status echoed
   * in the body. The Idempotency-Key replays the same response (including the
   * one-time production cust_ token).
   */
  async promote(
    ctx: RequestContext | undefined,
    customerID: string,
    req: PromoteCustomerRequest,
    idempotencyKey?: string,
  ): Promise<Customer> {
    const guard = this.c.requirePartner('customers.promote');
    if (guard) throw guard;
    if (!customerID) throw new Error('moss: customers.promote: customer_id is required');
    if (!req) throw new Error('moss: customers.promote: request is required');
    const out: Customer = {} as Customer;
    await this.c.doJSON(
      ctx,
      {
        method: 'POST',
        path: '/v1/partner/customers/' + encodeURIComponent(customerID) + '/promote',
        body: req,
        idempotencyKey,
      },
      out,
    );
    return out;
  }

  /**
   * Suspend suspends an active customer with a recorded reason. Reason is
   * required (non-empty); a missing reason returns ValidationError (422, code
   * "missing_reason"). An invalid from-state returns ConflictError (409, code
   * "invalid_transition").
   */
  async suspend(
    ctx: RequestContext | undefined,
    customerID: string,
    req: SuspendCustomerRequest,
  ): Promise<Customer> {
    const guard = this.c.requirePartner('customers.suspend');
    if (guard) throw guard;
    if (!customerID) throw new Error('moss: customers.suspend: customer_id is required');
    if (!req || !req.reason) {
      throw new Error('moss: customers.suspend: reason is required');
    }
    const out: Customer = {} as Customer;
    await this.c.doJSON(
      ctx,
      {
        method: 'POST',
        path: '/v1/partner/customers/' + encodeURIComponent(customerID) + '/suspend',
        body: req,
      },
      out,
    );
    return out;
  }

  /**
   * Reactivate reactivates a suspended customer, restoring exactly the
   * pre-suspension state. Requires a resolution record (issue_resolved ==
   * true, non-empty details). An invalid from-state returns ConflictError
   * (409, code "invalid_transition").
   */
  async reactivate(
    ctx: RequestContext | undefined,
    customerID: string,
    req: ReactivateCustomerRequest,
  ): Promise<Customer> {
    const guard = this.c.requirePartner('customers.reactivate');
    if (guard) throw guard;
    if (!customerID) throw new Error('moss: customers.reactivate: customer_id is required');
    if (!req || !req.resolution) {
      throw new Error('moss: customers.reactivate: resolution is required');
    }
    const out: Customer = {} as Customer;
    await this.c.doJSON(
      ctx,
      {
        method: 'POST',
        path: '/v1/partner/customers/' + encodeURIComponent(customerID) + '/reactivate',
        body: req,
      },
      out,
    );
    return out;
  }

  /**
   * Session mints a 15-minute full-access cust_ session token for a customer
   * the partner owns and returns the mint response plus a customer-scoped
   * Client bound to the raw cust_ token. The minted client's persona is
   * "customer" and its token is the minted cust_ token (not the prt_ token).
   *
   * A foreign or unknown customer returns NotFoundError (404, existence-non-
   * leak convention). A deactivated customer returns ConflictError (409, code
   * "customer_not_active").
   *
   * asCustomer is an alias for session (same method, same return).
   */
  async session(
    ctx: RequestContext | undefined,
    customerID: string,
    opts?: SessionOpts,
  ): Promise<SessionResult> {
    const guard = this.c.requirePartner('customers.session');
    if (guard) throw guard;
    if (!customerID) throw new Error('moss: customers.session: customer_id is required');
    const mint: SessionMint = {} as SessionMint;
    await this.c.doJSON(
      ctx,
      {
        method: 'POST',
        path: '/v1/partner/customers/' + encodeURIComponent(customerID) + '/session',
        idempotencyKey: opts?.idempotencyKey,
      },
      mint,
    );
    const scoped = new Client({
      token: mint.token,
      baseURL: this.c.getBaseURL(),
      timeoutMs: this.c.timeoutMs,
      maxRetries: this.c.maxRetries,
      userAgent: this.c.userAgent,
      fetchImpl: this.c.cfg.fetchImpl,
    });
    // Wire the resource namespaces onto the scoped client so the minted
    // cust_ client has the same surface as the root prt_ client.
    scoped.customers = new CustomersService(scoped);
    scoped.compliance = new ComplianceService(scoped);
    return { mint, client: scoped };
  }

  /** asCustomer is an alias for session. */
  async asCustomer(
    ctx: RequestContext | undefined,
    customerID: string,
    opts?: SessionOpts,
  ): Promise<SessionResult> {
    return this.session(ctx, customerID, opts);
  }

  /**
   * RevokeSession revokes a minted session token. If sessionID is non-empty,
   * only that session is revoked; if empty, ALL active partner-session tokens
   * for the customer are revoked. Returns on success (204). A foreign or
   * unknown customer returns NotFoundError (404). After revoke, calls made
   * with the minted cust_ token raise AuthError (401).
   *
   * NOTE: the vendored OpenAPI spec defines only POST (mint); DELETE is a
   * real backend route but is NOT served by the Prism mock. Mock-driven
   * tests for revoke must use a real-backend e2e harness (:3100).
   */
  async revokeSession(
    ctx: RequestContext | undefined,
    customerID: string,
    sessionID?: string,
  ): Promise<void> {
    const guard = this.c.requirePartner('customers.revokeSession');
    if (guard) throw guard;
    if (!customerID) throw new Error('moss: customers.revokeSession: customer_id is required');
    const body: Record<string, unknown> = {};
    if (sessionID) body.session_id = sessionID;
    await this.c.doNoContent(ctx, {
      method: 'DELETE',
      path: '/v1/partner/customers/' + encodeURIComponent(customerID) + '/session',
      body,
    });
  }

  /**
   * ComplianceReport fetches the signed compliance PDF for a customer the
   * partner owns. Returns the raw PDF bytes (application/pdf, %PDF- magic
   * header) plus a save helper. A foreign/unknown customer returns
   * NotFoundError (404). When the ML-DSA-44 signer is unconfigured the
   * backend fails closed (500) and the SDK surfaces ServerError — it never
   * returns an unsigned "compliance" artifact.
   */
  async complianceReport(
    ctx: RequestContext | undefined,
    customerID: string,
  ): Promise<ComplianceReportResult> {
    const guard = this.c.requirePartner('customers.complianceReport');
    if (guard) throw guard;
    if (!customerID) throw new Error('moss: customers.complianceReport: customer_id is required');
    const { contentType, bytes } = await this.c.doBytes(ctx, {
      method: 'GET',
      path: '/v1/partner/customers/' + encodeURIComponent(customerID) + '/compliance-report',
      accept: 'application/pdf',
    });
    return new ComplianceReportResult(contentType, bytes);
  }
}

/**
 * currentStatus extracts the current_status field echoed in a 409
 * invalid_transition body, or '' if absent. Convenience for callers handling
 * lifecycle conflict errors.
 */
export function currentStatus(err: unknown): string {
  return currentStatusFn(err);
}

/** Type guard for ConflictError (re-exported for callers). */
export { isConflict };
