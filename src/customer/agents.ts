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

export interface CreateAgentRequest {
  /** Agent identifier (unique within the org) */
  subject: string;
  /** Optional human-readable name */
  display_name?: string;
  /** Optional list of agent capabilities */
  capabilities?: string[];
  /** Optional tags */
  tags?: string[];
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

export interface Agent {
  id: string;
  org_id: string;
  subject: string;
  display_name: string | null;
  capabilities: string[];
  status: AgentStatus;
  created_at: string;
  initial_capability_token?: {
    token: string;
    token_id: string;
    execution_limit: number;
    expires_at: string;
    capabilities: string[];
  };
}

export class AgentsService {
  constructor(private readonly client: Client) {}

  /**
   * Register a new agent within the caller's organization (MOSS 2.0).
   *
   * Uses POST /v1/agents. Available via customer tokens (cust_) for
   * self-service users on passport/pro/team tiers. Returns the agent
   * record and an initial capability token (cap_).
   */
  async create(
    ctx: RequestContext | undefined,
    req: CreateAgentRequest
  ): Promise<Agent> {
    const res = await this.client.do(ctx, {
      method: 'POST',
      path: '/v1/agents',
      body: {
        subject: req.subject,
        display_name: req.display_name,
        capabilities: req.capabilities,
        tags: req.tags,
        metadata: req.metadata,
      },
    });
    return JSON.parse(res.body);
  }

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
