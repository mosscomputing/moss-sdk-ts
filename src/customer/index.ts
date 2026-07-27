/**
 * MOSS Customer SDK — TypeScript surface for customer-scoped operations.
 *
 * A Customer client is constructed with a customer token (cust_ prefix).
 * The default base URL is http://localhost:3100 (overridable).
 *
 * Customer persona (cust_) exposes these resource namespaces:
 *
 *   import { newCustomerClient } from '@moss/sdk/customer';
 *   const client = newCustomerClient({ token: process.env.MOSS_CUSTOMER_TOKEN });
 *   const agent = await client.agents.create({
 *     name: 'Support Bot',
 *     capabilities: { permittedActions: ['chat'] },
 *   });
 *   console.log(agent.id, agent.initialCapabilityToken);
 *
 * Resource namespaces:
 *   - agents: create / list / get / suspend / reactivate / revoke
 *   - capabilities: create (issue scoped capability tokens)
 *   - compliance: status / frameworks / report
 *   - policies: list / create / evaluate
 *   - audit: query / verify / chain
 *
 * Reuses the same Client, error hierarchy, and retry logic from the Partner SDK.
 */

import { Client } from '../partner/client.js';
import type { Config } from '../partner/client.js';
import { AgentsService } from './agents.js';
import { CapabilitiesService } from './capabilities.js';
import { ComplianceService } from './compliance.js';
import { PoliciesService } from './policies.js';
import { AuditService } from './audit.js';

// Re-export client config and errors from partner SDK (shared infrastructure)
export {
  Client,
  DEFAULT_BASE_URL,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_MAX_RETRIES,
  INITIAL_BACKOFF_MS,
  MAX_BACKOFF_MS,
  PREFIX_CUSTOMER,
  inferPersona,
} from '../partner/client.js';
export type { Config, Persona, RequestContext } from '../partner/client.js';

export {
  APIError,
  AuthError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  ValidationError,
  ServerError,
  asTypedError,
  buildAPIError,
  parseRetryAfterMs,
  isAuth,
  isNotFound,
  isRateLimit,
  isValidation,
  isConflict,
  isServer,
  codeOf,
  statusOf,
  currentStatus,
} from '../partner/errors.js';
export type { Headers, Body } from '../partner/errors.js';

export { AgentsService } from './agents.js';
export type {
  Agent,
  AgentStatus,
  CreateAgentRequest,
  UpdateAgentRequest,
  SuspendAgentRequest,
  ReactivateAgentRequest,
  RevokeAgentRequest,
  ListAgentsOptions,
  AgentListResponse,
  BehavioralFingerprint,
  AgentCapabilities,
  BehavioralBounds,
  ModelConfig,
} from './agents.js';

export { CapabilitiesService } from './capabilities.js';
export type {
  CapabilityToken,
  CreateCapabilityTokenRequest,
  CapabilityConstraints,
  CapabilityPermissions,
} from './capabilities.js';

export { ComplianceService } from './compliance.js';
export type {
  ComplianceStatus,
  ComplianceFramework,
  ComplianceReport,
  ComplianceReportRequest,
  ComplianceIssue,
} from './compliance.js';

export { PoliciesService } from './policies.js';
export type {
  Policy,
  PolicyRule,
  CreatePolicyRequest,
  UpdatePolicyRequest,
  PolicyEvaluation,
  EvaluatePolicyRequest,
  ListPoliciesOptions,
  PolicyListResponse,
  PolicySource,
} from './policies.js';

export { AuditService } from './audit.js';
export type {
  AuditLogEntry,
  QueryAuditLogsRequest,
  AuditQueryResponse,
  VerifyEnvelopeResult,
  ProvenanceChain,
} from './audit.js';

/**
 * newCustomerClient constructs a Customer SDK Client and wires its resource
 * namespaces (agents, capabilities, compliance, policies, audit).
 * Convenience wrapper around `new Client(cfg)`.
 */
export function newCustomerClient(cfg: Config): Client {
  const c = new Client(cfg);
  c.agents = new AgentsService(c);
  c.capabilities = new CapabilitiesService(c);
  c.compliance = new ComplianceService(c);
  c.policies = new PoliciesService(c);
  c.audit = new AuditService(c);
  return c;
}
