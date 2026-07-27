/**
 * Customer SDK — Compliance Service
 *
 * Compliance status reporting, framework tracking, and report generation
 * for regulatory and governance requirements.
 */

import type { Client } from '../partner/client.js';
import type { RequestContext } from '../partner/client.js';

export interface ComplianceIssue {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  remediationUrl?: string;
}

export interface ComplianceStatus {
  score: number;
  status: 'compliant' | 'at_risk' | 'non_compliant';
  issues: ComplianceIssue[];
  lastCheckedAt: string;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  code: string;
  enabled: boolean;
  coverage: number;
}

export interface ComplianceReportRequest {
  frameworks: string[];
  format: 'pdf' | 'json';
  period?: string;
}

export interface ComplianceReport {
  id: string;
  frameworks: string[];
  format: 'pdf' | 'json';
  period?: string;
  downloadUrl: string;
  generatedAt: string;
  expiresAt: string;
}

export interface ComplianceFrameworkResponse {
  data: ComplianceFramework[];
}

export class ComplianceService {
  constructor(private readonly client: Client) {}

  /**
   * Get compliance status for the customer organization.
   */
  async status(ctx: RequestContext | undefined): Promise<ComplianceStatus> {
    const res = await this.client.do(ctx, {
      method: 'GET',
      path: '/v1/customer/compliance/status',
    });
    return JSON.parse(res.body);
  }

  /**
   * Get list of active compliance frameworks.
   */
  async frameworks(ctx: RequestContext | undefined): Promise<ComplianceFrameworkResponse> {
    const res = await this.client.do(ctx, {
      method: 'GET',
      path: '/v1/customer/compliance/frameworks',
    });
    return JSON.parse(res.body);
  }

  /**
   * Generate a compliance report for specified frameworks.
   */
  async report(
    ctx: RequestContext | undefined,
    req: ComplianceReportRequest,
    idempotencyKey?: string
  ): Promise<ComplianceReport> {
    const res = await this.client.do(ctx, {
      method: 'POST',
      path: '/v1/customer/compliance/reports',
      body: req,
      idempotencyKey,
    });
    return JSON.parse(res.body);
  }
}
