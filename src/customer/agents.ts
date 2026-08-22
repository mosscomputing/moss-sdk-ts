/**
 * Customer SDK — Agents Service
 *
 * Customer-facing agent operations. Agent CRUD (create, list, get, update,
 * suspend, reactivate) requires internal RBAC auth (console users) and is
 * NOT available via customer tokens. The only customer-accessible agent
 * operation is revocation via POST /v1/revoke.
 */

import type { Client } from '../partner/client.js';
import type { RequestContext } from '../partner/client.js';

export type AgentStatus = 'active' | 'suspended' | 'revoked';

export interface RevokeAgentRequest {
  /** Agent UUID to revoke */
  targetId: string;
}

export interface RevokeAgentResponse {
  affected: {
    direct: number;
    delegated: number;
    total: number;
  };
  propagation: {
    channels_notified: string[];
    status: string;
  };
}

export class AgentsService {
  constructor(private readonly client: Client) {}

  /**
   * Permanently revoke an agent within the caller's organization.
   *
   * Uses POST /v1/revoke with type="agent". This is the only
   * customer-accessible agent lifecycle endpoint. Agent registration,
   * listing, suspension, and reactivation require internal RBAC auth
   * (console users) and are not exposed via customer tokens.
   *
   * Returns the blast radius (affected tokens/agents) and cross-channel
   * propagation status.
   */
  async revoke(
    ctx: RequestContext | undefined,
    req: RevokeAgentRequest,
    idempotencyKey?: string
  ): Promise<RevokeAgentResponse> {
    const res = await this.client.do(ctx, {
      method: 'POST',
      path: '/v1/revoke',
      body: {
        type: 'agent',
        target_id: req.targetId,
      },
      idempotencyKey,
    });
    return JSON.parse(res.body);
  }
}
