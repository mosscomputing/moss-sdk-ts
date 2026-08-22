/**
 * Customer SDK — Policies Service
 *
 * Customer-facing policy evaluation (dry run). Policy CRUD (list, create,
 * update, delete) requires internal RBAC auth (console users) and is NOT
 * available via customer tokens. Only POST /v1/policies/evaluate uses
 * customer token auth (get_customer_org).
 */

import type { Client } from '../partner/client.js';
import type { RequestContext } from '../partner/client.js';

export type PolicyAction = 'block' | 'allow' | 'require_approval';
export type PolicySeverity = 'critical' | 'high' | 'medium' | 'low';

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
   * Evaluate a potential action against active policies (dry run).
   *
   * POST /v1/policies/evaluate (customer token auth)
   *
   * Resolves system + partner-default + customer policies and evaluates
   * the proposed action without creating an execution envelope, signature,
   * or persisted violation. Returns the decision (allow/block/escalate)
   * plus contributing policies.
   */
  async evaluate(
    ctx: RequestContext | undefined,
    req: EvaluatePolicyRequest
  ): Promise<PolicyEvaluation> {
    const res = await this.client.do(ctx, {
      method: 'POST',
      path: '/v1/policies/evaluate',
      body: req,
    });
    return JSON.parse(res.body);
  }
}
