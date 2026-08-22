/**
 * Customer SDK — Capabilities Service
 *
 * Issues scoped capability tokens for agents with fine-grained permissions,
 * resource scope, and execution constraints.
 *
 * Uses POST /v1/capabilities (customer token auth via get_customer_org).
 * The path is /v1/capabilities, NOT /v1/customer/capabilities.
 */

import type { Client } from '../partner/client.js';
import type { RequestContext } from '../partner/client.js';

export interface CapabilityPermissions {
  permissions: string[];
  resourceScope: string[];
  actionTypes: string[];
}

export interface CapabilityConstraints {
  executionLimit?: number;
  expiresInSeconds: number;
  classificationCeiling?: string[];
}

export interface CapabilityContext {
  taskId?: string;
  purpose?: string;
  humanPrincipal?: string;
}

export interface CreateCapabilityTokenRequest {
  agentId: string;
  capabilities: CapabilityPermissions;
  constraints: CapabilityConstraints;
  context?: CapabilityContext;
}

export interface CapabilityToken {
  capabilityToken: string;
  expiresAt: string;
  constraints: CapabilityConstraints;
}

export class CapabilitiesService {
  constructor(private readonly client: Client) {}

  /**
   * Create a scoped capability token for an agent.
   * POST /v1/capabilities
   *
   * Issues a cap_ token that attenuates against the agent's registered
   * capabilities. Refuses suspended/foreign/nonexistent agents. Bounded
   * by the customer's capability_tokens_per_hour budget.
   */
  async create(
    ctx: RequestContext | undefined,
    req: CreateCapabilityTokenRequest,
    idempotencyKey?: string
  ): Promise<CapabilityToken> {
    const res = await this.client.do(ctx, {
      method: 'POST',
      path: '/v1/capabilities',
      body: req,
      idempotencyKey,
    });
    return JSON.parse(res.body);
  }
}
