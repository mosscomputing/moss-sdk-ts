/**
 * Customer SDK — Passports Service (MOSS 2.0)
 *
 * Agent Passport management for self-service customers. Passports are
 * cryptographically signed (ML-DSA-44) agent identity documents.
 */

import type { Client } from '../partner/client.js';
import type { RequestContext } from '../partner/client.js';

export interface Passport {
  version: string;
  passport_id: string;
  agent_subject: string;
  agent_display_name: string | null;
  owner_org_name: string;
  capabilities: string[];
  policy_scope: Record<string, unknown>;
  issued_at: string;
  expires_at: string;
  revocation_url: string;
  verification_url: string;
  hash: string;
  signature: string;
  signing_key_id: string;
}

export interface PassportStatus {
  valid: boolean;
  revoked: boolean;
  expired: boolean;
  expires_at: string;
}

export interface PassportListItem {
  passport_id: string;
  agent_subject: string;
  agent_display_name: string | null;
  issued_at: string;
  expires_at: string;
  revoked: boolean;
}

export interface PassportListResponse {
  passports: PassportListItem[];
}

export interface RenewPassportRequest {
  agent_id: string;
}

export class PassportsService {
  constructor(private readonly client: Client) {}

  /**
   * Get a passport by its public ID (pp_xxx). No auth required for this
   * endpoint, but using it via the customer SDK provides auth context.
   */
  async get(
    ctx: RequestContext | undefined,
    passportId: string
  ): Promise<Passport> {
    const res = await this.client.do(ctx, {
      method: 'GET',
      path: `/v1/passport/${passportId}`,
    });
    const parsed = JSON.parse(res.body);
    return parsed.passport ?? parsed;
  }

  /**
   * Quick validity check for a passport.
   */
  async getStatus(
    ctx: RequestContext | undefined,
    passportId: string
  ): Promise<PassportStatus> {
    const res = await this.client.do(ctx, {
      method: 'GET',
      path: `/v1/passport/${passportId}/status`,
    });
    return JSON.parse(res.body);
  }

  /**
   * Renew an expiring passport for an agent. Issues a new passport with
   * a fresh TTL. The old passport remains (append-only) but expires naturally.
   */
  async renew(
    ctx: RequestContext | undefined,
    req: RenewPassportRequest
  ): Promise<Passport> {
    const res = await this.client.do(ctx, {
      method: 'POST',
      path: '/v1/passport/renew',
      body: { agent_id: req.agent_id },
    });
    const parsed = JSON.parse(res.body);
    return parsed.passport ?? parsed;
  }

  /**
   * List all passports for the authenticated org.
   */
  async list(
    ctx: RequestContext | undefined
  ): Promise<PassportListResponse> {
    const res = await this.client.do(ctx, {
      method: 'GET',
      path: '/v1/passports',
    });
    return JSON.parse(res.body);
  }
}
