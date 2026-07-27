/**
 * Customer SDK — Capabilities Service
 *
 * Issues scoped capability tokens for agents with fine-grained permissions,
 * resource scope, and execution constraints.
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
   */
  async create(
    ctx: RequestContext | undefined,
    req: CreateCapabilityTokenRequest,
    idempotencyKey?: string
  ): Promise<CapabilityToken> {
    const res = await this.client.do(ctx, {
      method: 'POST',
      path: '/v1/customer/capabilities',
      body: req,
      idempotencyKey,
    });
    return JSON.parse(res.body);
  }
}
