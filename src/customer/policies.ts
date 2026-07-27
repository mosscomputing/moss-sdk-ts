/**
 * Customer SDK — Policies Service
 *
 * Policy management, creation, evaluation, and inheritance tracking
 * for agent action governance.
 */

import type { Client } from '../partner/client.js';
import type { RequestContext } from '../partner/client.js';

export type PolicySource = 'system' | 'partner' | 'customer';
export type PolicyAction = 'block' | 'allow' | 'require_approval';
export type PolicySeverity = 'critical' | 'high' | 'medium' | 'low';

export interface PolicyRule {
  field: string;
  operator: string;
  values: string[];
}

export interface Policy {
  id: string;
  name: string;
  description?: string;
  rules: PolicyRule[];
  action: PolicyAction;
  severity: PolicySeverity;
  source: PolicySource;
  createdAt: string;
  updatedAt: string;
}

export interface CreatePolicyRequest {
  name: string;
  description?: string;
  rules: PolicyRule[];
  action: PolicyAction;
  severity: PolicySeverity;
}

export interface UpdatePolicyRequest {
  name?: string;
  description?: string;
  rules?: PolicyRule[];
  action?: PolicyAction;
  severity?: PolicySeverity;
}

export interface ListPoliciesOptions {
  source?: PolicySource;
  limit?: number;
  offset?: number;
}

export interface PolicyListResponse {
  data: Policy[];
  total: number;
  limit: number;
  offset: number;
}

export interface EvaluatePolicyRequest {
  action: string;
  input?: string;
  output?: string;
}

export interface PolicyEvaluation {
  wouldBlock: boolean;
  violatedPolicies: string[];
  action: string;
}

export class PoliciesService {
  constructor(private readonly client: Client) {}

  /**
   * List policies (inherited from system/partner + customer-defined).
   */
  async list(
    ctx: RequestContext | undefined,
    opts?: ListPoliciesOptions
  ): Promise<PolicyListResponse> {
    const params = new URLSearchParams();
    if (opts?.source) params.set('source', opts.source);
    if (opts?.limit) params.set('limit', String(opts.limit));
    if (opts?.offset) params.set('offset', String(opts.offset));

    const query = params.toString();
    const path = query ? `/v1/customer/policies?${query}` : '/v1/customer/policies';

    const res = await this.client.do(ctx, { method: 'GET', path });
    return JSON.parse(res.body);
  }

  /**
   * Create a custom policy.
   */
  async create(
    ctx: RequestContext | undefined,
    req: CreatePolicyRequest,
    idempotencyKey?: string
  ): Promise<Policy> {
    const res = await this.client.do(ctx, {
      method: 'POST',
      path: '/v1/customer/policies',
      body: req,
      idempotencyKey,
    });
    return JSON.parse(res.body);
  }

  /**
   * Update a custom policy.
   */
  async update(
    ctx: RequestContext | undefined,
    policyId: string,
    req: UpdatePolicyRequest,
    idempotencyKey?: string
  ): Promise<Policy> {
    const res = await this.client.do(ctx, {
      method: 'PATCH',
      path: `/v1/customer/policies/${encodeURIComponent(policyId)}`,
      body: req,
      idempotencyKey,
    });
    return JSON.parse(res.body);
  }

  /**
   * Evaluate a potential action against active policies (dry run).
   */
  async evaluate(
    ctx: RequestContext | undefined,
    req: EvaluatePolicyRequest
  ): Promise<PolicyEvaluation> {
    const res = await this.client.do(ctx, {
      method: 'POST',
      path: '/v1/customer/policies/evaluate',
      body: req,
    });
    return JSON.parse(res.body);
  }
}
