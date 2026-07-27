/**
 * Customer SDK — Agents Service
 *
 * Manages agent registration, lifecycle, and behavioral monitoring within
 * a customer organization.
 */

import type { Client } from '../partner/client.js';
import type { RequestContext } from '../partner/client.js';

export type AgentStatus = 'active' | 'suspended' | 'revoked';

export interface AgentCapabilities {
  permittedActions: string[];
  permittedResources: string[];
  permittedClassifications: string[];
  maxDelegationDepth?: number;
}

export interface BehavioralBounds {
  expectedActionsPerHour: { min: number; max: number };
  expectedDelegationRate?: number;
}

export interface ModelConfig {
  provider: string;
  modelId: string;
}

export interface BehavioralFingerprint {
  anomalyScore: number;
  lastAnalyzedAt: string;
  totalActions: number;
}

export interface Agent {
  id: string;
  name: string;
  description?: string;
  status: AgentStatus;
  capabilities: AgentCapabilities;
  behavioralBounds?: BehavioralBounds;
  model?: ModelConfig;
  behavioralFingerprint?: BehavioralFingerprint;
  initialCapabilityToken: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateAgentRequest {
  name: string;
  description?: string;
  capabilities: AgentCapabilities;
  behavioralBounds?: BehavioralBounds;
  model?: ModelConfig;
}

export interface UpdateAgentRequest {
  name?: string;
  description?: string;
  capabilities?: Partial<AgentCapabilities>;
  behavioralBounds?: Partial<BehavioralBounds>;
}

export interface SuspendAgentRequest {
  reason: string;
}

export interface ReactivateAgentRequest {
  reason?: string;
}

export interface RevokeAgentRequest {
  reason: string;
}

export interface ListAgentsOptions {
  status?: AgentStatus;
  limit?: number;
  offset?: number;
}

export interface AgentListResponse {
  data: Agent[];
  total: number;
  limit: number;
  offset: number;
}

export class AgentsService {
  constructor(private readonly client: Client) {}

  /**
   * Register a new agent.
   */
  async create(
    ctx: RequestContext | undefined,
    req: CreateAgentRequest,
    idempotencyKey?: string
  ): Promise<Agent> {
    const res = await this.client.do(ctx, {
      method: 'POST',
      path: '/v1/customer/agents',
      body: req,
      idempotencyKey,
    });
    return JSON.parse(res.body);
  }

  /**
   * List agents in this customer organization.
   */
  async list(
    ctx: RequestContext | undefined,
    opts?: ListAgentsOptions
  ): Promise<AgentListResponse> {
    const params = new URLSearchParams();
    if (opts?.status) params.set('status', opts.status);
    if (opts?.limit) params.set('limit', String(opts.limit));
    if (opts?.offset) params.set('offset', String(opts.offset));

    const query = params.toString();
    const path = query ? `/v1/customer/agents?${query}` : '/v1/customer/agents';

    const res = await this.client.do(ctx, { method: 'GET', path });
    return JSON.parse(res.body);
  }

  /**
   * Get agent details and behavioral fingerprint.
   */
  async get(ctx: RequestContext | undefined, agentId: string): Promise<Agent> {
    const res = await this.client.do(ctx, {
      method: 'GET',
      path: `/v1/customer/agents/${encodeURIComponent(agentId)}`,
    });
    return JSON.parse(res.body);
  }

  /**
   * Update agent configuration.
   */
  async update(
    ctx: RequestContext | undefined,
    agentId: string,
    req: UpdateAgentRequest,
    idempotencyKey?: string
  ): Promise<Agent> {
    const res = await this.client.do(ctx, {
      method: 'PATCH',
      path: `/v1/customer/agents/${encodeURIComponent(agentId)}`,
      body: req,
      idempotencyKey,
    });
    return JSON.parse(res.body);
  }

  /**
   * Suspend agent (can be reactivated).
   */
  async suspend(
    ctx: RequestContext | undefined,
    agentId: string,
    req: SuspendAgentRequest,
    idempotencyKey?: string
  ): Promise<Agent> {
    const res = await this.client.do(ctx, {
      method: 'POST',
      path: `/v1/customer/agents/${encodeURIComponent(agentId)}/suspend`,
      body: req,
      idempotencyKey,
    });
    return JSON.parse(res.body);
  }

  /**
   * Reactivate suspended agent.
   */
  async reactivate(
    ctx: RequestContext | undefined,
    agentId: string,
    req?: ReactivateAgentRequest,
    idempotencyKey?: string
  ): Promise<Agent> {
    const res = await this.client.do(ctx, {
      method: 'POST',
      path: `/v1/customer/agents/${encodeURIComponent(agentId)}/reactivate`,
      body: req || {},
      idempotencyKey,
    });
    return JSON.parse(res.body);
  }

  /**
   * Permanently revoke agent (cannot be reactivated).
   */
  async revoke(
    ctx: RequestContext | undefined,
    agentId: string,
    req: RevokeAgentRequest,
    idempotencyKey?: string
  ): Promise<void> {
    await this.client.do(ctx, {
      method: 'POST',
      path: `/v1/customer/agents/${encodeURIComponent(agentId)}/revoke`,
      body: req,
      idempotencyKey,
    });
  }
}
