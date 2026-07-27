/**
 * Customer SDK — Audit Service
 *
 * Audit log querying, envelope verification, and provenance chain tracking
 * for policy enforcement and governance evidence.
 */

import type { Client } from '../partner/client.js';
import type { RequestContext } from '../partner/client.js';

export interface AuditAction {
  type: string;
  input?: string;
  output?: string;
}

export interface PolicyEvaluationResult {
  result: string;
  violatedPolicies?: string[];
}

export interface AuditLogEntry {
  id: string;
  agentId: string;
  action: AuditAction;
  policyEvaluation: PolicyEvaluationResult;
  createdAt: string;
  envelopeId: string;
  parentEnvelopeId?: string;
  signature?: string;
}

export interface QueryAuditLogsRequest {
  agentId?: string;
  startTime?: string;
  endTime?: string;
  actions?: string[];
  limit?: number;
  offset?: number;
}

export interface AuditQueryResponse {
  data: AuditLogEntry[];
  total: number;
  limit: number;
  offset: number;
}

export interface VerifyEnvelopeResult {
  valid: boolean;
  chainIntact: boolean;
  envelopeId: string;
  signature?: string;
  verifiedAt: string;
}

export interface ProvenanceChain {
  id: string;
  agentId: string;
  action: AuditAction;
  parentEnvelopeId?: string;
  createdAt: string;
  signature?: string;
}

export class AuditService {
  constructor(private readonly client: Client) {}

  /**
   * Query audit logs with filters.
   */
  async query(
    ctx: RequestContext | undefined,
    req: QueryAuditLogsRequest
  ): Promise<AuditQueryResponse> {
    const res = await this.client.do(ctx, {
      method: 'POST',
      path: '/v1/customer/audit/query',
      body: req,
    });
    return JSON.parse(res.body);
  }

  /**
   * Verify the integrity of an audit envelope.
   */
  async verify(
    ctx: RequestContext | undefined,
    envelopeId: string
  ): Promise<VerifyEnvelopeResult> {
    const res = await this.client.do(ctx, {
      method: 'GET',
      path: `/v1/customer/audit/envelopes/${encodeURIComponent(envelopeId)}/verify`,
    });
    return JSON.parse(res.body);
  }

  /**
   * Get the full provenance chain for an envelope.
   */
  async chain(
    ctx: RequestContext | undefined,
    envelopeId: string
  ): Promise<ProvenanceChain[]> {
    const res = await this.client.do(ctx, {
      method: 'GET',
      path: `/v1/customer/audit/envelopes/${encodeURIComponent(envelopeId)}/chain`,
    });
    return JSON.parse(res.body);
  }
}
