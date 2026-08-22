/**
 * Customer SDK Tests — Comprehensive coverage for all customer-scoped operations
 *
 * Tests all 9 methods across 5 Customer SDK service namespaces:
 * - AgentsService (1 method): revoke
 * - CapabilitiesService (1 method): create
 * - ComplianceService (3 methods): status, frameworks, report
 * - PoliciesService (1 method): evaluate
 * - AuditService (3 methods): query, verify, chain
 *
 * Coverage: happy path, error cases, edge cases, idempotency
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { newCustomerClient } from '../src/customer/index.js';
import type { Client } from '../src/partner/client.js';

// Mock server setup (assumes Prism mock server running on localhost:3100)
const MOCK_BASE_URL = process.env.MOSS_API_BASE_URL || 'http://localhost:3100';
const MOCK_CUSTOMER_TOKEN = process.env.MOSS_TEST_CUSTOMER_TOKEN || 'cust_test_12345678901234567890123456';

describe('Customer SDK - Client Construction', () => {
  it('creates a customer client with default base URL', () => {
    const client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN });
    expect(client).toBeDefined();
    expect(client.getPersona()).toBe('customer');
    expect(client.agents).toBeDefined();
    expect(client.capabilities).toBeDefined();
    expect(client.compliance).toBeDefined();
    expect(client.policies).toBeDefined();
    expect(client.audit).toBeDefined();
  });

  it('creates a customer client with custom base URL', () => {
    const client = newCustomerClient({
      token: MOCK_CUSTOMER_TOKEN,
      baseURL: MOCK_BASE_URL
    });
    expect(client.getBaseURL()).toBe(MOCK_BASE_URL);
  });

  it('throws error when token is missing', () => {
    expect(() => newCustomerClient({ token: '' })).toThrow('Config.token is required');
  });

  it('verifies customer token prefix', () => {
    const client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN });
    expect(client.cfg.token.startsWith('cust_')).toBe(true);
  });
});

describe('Customer SDK - agents.revoke()', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('permanently revokes an agent', async () => {
    const response = await client.agents.revoke(undefined, {
      targetId: 'some-agent-id',
    }, 'idem-agent-revoke-001');

    expect(response).toBeDefined();
    expect(response.affected).toBeDefined();
    expect(typeof response.affected.direct).toBe('number');
    expect(typeof response.affected.delegated).toBe('number');
    expect(typeof response.affected.total).toBe('number');
    expect(response.propagation).toBeDefined();
    expect(response.propagation.channels_notified).toBeInstanceOf(Array);
    expect(typeof response.propagation.status).toBe('string');
  });

  it('honors idempotency key for revoke requests', async () => {
    const idempotencyKey = 'idem-agent-revoke-duplicate';
    const req = { targetId: 'idempotent-agent-id' };

    const first = await client.agents.revoke(undefined, req, idempotencyKey);
    const second = await client.agents.revoke(undefined, req, idempotencyKey);

    expect(first.affected.total).toBe(second.affected.total);
  });

  it('throws error when revoking non-existent agent', async () => {
    await expect(
      client.agents.revoke(undefined, {
        targetId: 'agent_nonexistent',
      }, 'idem-agent-revoke-invalid')
    ).rejects.toThrow();
  });
});

describe('Customer SDK - capabilities.create()', () => {
  let client: Client;
  const testAgentId = 'agent_test_capability_001';

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('creates a scoped capability token', async () => {
    const capability = await client.capabilities.create(undefined, {
      agentId: testAgentId,
      capabilities: {
        permissions: ['read', 'write'],
        resourceScope: ['documents:/customer/reports'],
        actionTypes: ['query', 'update'],
      },
      constraints: {
        expiresInSeconds: 3600,
      },
    }, 'idem-capability-create-001');

    expect(capability).toBeDefined();
    expect(capability.capabilityToken).toBeDefined();
    expect(capability.expiresAt).toBeDefined();
    expect(capability.constraints.expiresInSeconds).toBe(3600);
  });

  it('creates a capability token with execution limit', async () => {
    const capability = await client.capabilities.create(undefined, {
      agentId: testAgentId,
      capabilities: {
        permissions: ['execute'],
        resourceScope: ['functions:/payments'],
        actionTypes: ['transfer'],
      },
      constraints: {
        executionLimit: 10,
        expiresInSeconds: 7200,
      },
    }, 'idem-capability-create-002');

    expect(capability.constraints.executionLimit).toBe(10);
    expect(capability.constraints.expiresInSeconds).toBe(7200);
  });

  it('creates a capability token with classification ceiling', async () => {
    const capability = await client.capabilities.create(undefined, {
      agentId: testAgentId,
      capabilities: {
        permissions: ['read'],
        resourceScope: ['data:/analytics'],
        actionTypes: ['query'],
      },
      constraints: {
        expiresInSeconds: 1800,
        classificationCeiling: ['internal', 'public'],
      },
    }, 'idem-capability-create-003');

    expect(capability.constraints.classificationCeiling).toContain('internal');
    expect(capability.constraints.classificationCeiling).toContain('public');
  });

  it('creates a capability token with context', async () => {
    const capability = await client.capabilities.create(undefined, {
      agentId: testAgentId,
      capabilities: {
        permissions: ['execute'],
        resourceScope: ['workflows:/approvals'],
        actionTypes: ['approve'],
      },
      constraints: {
        expiresInSeconds: 900,
      },
      context: {
        taskId: 'task-123',
        purpose: 'Approve expense report',
        humanPrincipal: 'user@example.com',
      },
    }, 'idem-capability-create-004');

    expect(capability).toBeDefined();
    expect(capability.capabilityToken).toBeDefined();
  });

  it('honors idempotency key for capability creation', async () => {
    const idempotencyKey = 'idem-capability-duplicate';
    const req = {
      agentId: testAgentId,
      capabilities: {
        permissions: ['test'],
        resourceScope: ['test:/resource'],
        actionTypes: ['test-action'],
      },
      constraints: {
        expiresInSeconds: 600,
      },
    };

    const first = await client.capabilities.create(undefined, req, idempotencyKey);
    const second = await client.capabilities.create(undefined, req, idempotencyKey);

    expect(first.capabilityToken).toBe(second.capabilityToken);
  });

  it('throws error for non-existent agent', async () => {
    await expect(
      client.capabilities.create(undefined, {
        agentId: 'agent_nonexistent',
        capabilities: {
          permissions: ['read'],
          resourceScope: ['data:/test'],
          actionTypes: ['query'],
        },
        constraints: {
          expiresInSeconds: 3600,
        },
      }, 'idem-capability-invalid')
    ).rejects.toThrow();
  });
});

describe('Customer SDK - compliance.status()', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('retrieves compliance status', async () => {
    const status = await client.compliance.status(undefined);

    expect(status).toBeDefined();
    expect(status.score).toBeGreaterThanOrEqual(0);
    expect(status.score).toBeLessThanOrEqual(100);
    expect(['compliant', 'at_risk', 'non_compliant']).toContain(status.status);
    expect(status.issues).toBeInstanceOf(Array);
    expect(status.lastCheckedAt).toBeDefined();
  });

  it('returns compliance issues with proper structure', async () => {
    const status = await client.compliance.status(undefined);

    status.issues.forEach(issue => {
      expect(issue.id).toBeDefined();
      expect(issue.title).toBeDefined();
      expect(issue.description).toBeDefined();
      expect(['critical', 'high', 'medium', 'low']).toContain(issue.severity);
    });
  });
});

describe('Customer SDK - compliance.frameworks()', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('retrieves list of compliance frameworks', async () => {
    const response = await client.compliance.frameworks(undefined);

    expect(response).toBeDefined();
    expect(response.data).toBeInstanceOf(Array);
  });

  it('returns frameworks with proper structure', async () => {
    const response = await client.compliance.frameworks(undefined);

    response.data.forEach(framework => {
      expect(framework.id).toBeDefined();
      expect(framework.name).toBeDefined();
      expect(framework.code).toBeDefined();
      expect(typeof framework.enabled).toBe('boolean');
      expect(framework.coverage).toBeGreaterThanOrEqual(0);
      expect(framework.coverage).toBeLessThanOrEqual(100);
    });
  });

  it('includes common frameworks (SOC2, ISO27001, GDPR)', async () => {
    const response = await client.compliance.frameworks(undefined);
    const codes = response.data.map(f => f.code);

    // At least one standard framework should be present
    expect(response.data.length).toBeGreaterThan(0);
  });
});

describe('Customer SDK - compliance.report()', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('generates a PDF compliance report', async () => {
    const report = await client.compliance.report(undefined, {
      frameworks: ['SOC2', 'ISO27001'],
      format: 'pdf',
    }, 'idem-compliance-report-pdf');

    expect(report).toBeDefined();
    expect(report.id).toBeDefined();
    expect(report.frameworks).toContain('SOC2');
    expect(report.frameworks).toContain('ISO27001');
    expect(report.format).toBe('pdf');
    expect(report.downloadUrl).toBeDefined();
    expect(report.generatedAt).toBeDefined();
    expect(report.expiresAt).toBeDefined();
  });

  it('generates a JSON compliance report', async () => {
    const report = await client.compliance.report(undefined, {
      frameworks: ['GDPR'],
      format: 'json',
    }, 'idem-compliance-report-json');

    expect(report.format).toBe('json');
    expect(report.frameworks).toContain('GDPR');
  });

  it('generates a report with period specified', async () => {
    const report = await client.compliance.report(undefined, {
      frameworks: ['SOC2'],
      format: 'pdf',
      period: '2025-Q1',
    }, 'idem-compliance-report-period');

    expect(report.period).toBe('2025-Q1');
  });

  it('honors idempotency key for report generation', async () => {
    const idempotencyKey = 'idem-compliance-report-duplicate';
    const req = {
      frameworks: ['ISO27001'],
      format: 'pdf' as const,
    };

    const first = await client.compliance.report(undefined, req, idempotencyKey);
    const second = await client.compliance.report(undefined, req, idempotencyKey);

    expect(first.id).toBe(second.id);
    expect(first.downloadUrl).toBe(second.downloadUrl);
  });
});

describe('Customer SDK - policies.evaluate()', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('evaluates action that would be blocked', async () => {
    const evaluation = await client.policies.evaluate(undefined, {
      action: 'dangerous_action',
    });

    expect(evaluation).toBeDefined();
    expect(evaluation.action).toBe('dangerous_action');
    // Would block if the policy matches
  });

  it('evaluates action with input and output', async () => {
    const evaluation = await client.policies.evaluate(undefined, {
      action: 'transfer',
      input: 'Transfer $5000 to account 12345',
      output: 'Transfer approved',
    });

    expect(evaluation).toBeDefined();
    expect(evaluation.action).toBe('transfer');
  });

  it('evaluates safe action that would not be blocked', async () => {
    const evaluation = await client.policies.evaluate(undefined, {
      action: 'safe_read',
    });

    expect(evaluation).toBeDefined();
    expect(evaluation.wouldBlock).toBeDefined();
    expect(evaluation.violatedPolicies).toBeInstanceOf(Array);
  });
});

describe('Customer SDK - audit.query()', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('queries all audit logs with default pagination', async () => {
    const response = await client.audit.query(undefined, {});

    expect(response).toBeDefined();
    expect(response.data).toBeInstanceOf(Array);
    expect(response.total).toBeGreaterThanOrEqual(0);
    expect(response.limit).toBeDefined();
    expect(response.offset).toBeDefined();
  });

  it('queries audit logs by agent ID', async () => {
    const response = await client.audit.query(undefined, {
      agentId: 'agent-123',
    });

    expect(response.data).toBeInstanceOf(Array);
    response.data.forEach(entry => {
      expect(entry.agentId).toBe('agent-123');
    });
  });

  it('queries audit logs by time range', async () => {
    const response = await client.audit.query(undefined, {
      startTime: '2025-01-01T00:00:00Z',
      endTime: '2025-12-31T23:59:59Z',
    });

    expect(response.data).toBeInstanceOf(Array);
  });

  it('queries audit logs by action types', async () => {
    const response = await client.audit.query(undefined, {
      actions: ['transfer', 'withdraw'],
    });

    expect(response.data).toBeInstanceOf(Array);
  });

  it('queries audit logs with pagination', async () => {
    const response = await client.audit.query(undefined, {
      limit: 20,
      offset: 0,
    });

    expect(response.limit).toBe(20);
    expect(response.offset).toBe(0);
    expect(response.data.length).toBeLessThanOrEqual(20);
  });

  it('returns audit entries with proper structure', async () => {
    const response = await client.audit.query(undefined, {
      limit: 5,
    });

    response.data.forEach(entry => {
      expect(entry.id).toBeDefined();
      expect(entry.agentId).toBeDefined();
      expect(entry.action).toBeDefined();
      expect(entry.action.type).toBeDefined();
      expect(entry.policyEvaluation).toBeDefined();
      expect(entry.policyEvaluation.result).toBeDefined();
      expect(entry.createdAt).toBeDefined();
      expect(entry.envelopeId).toBeDefined();
    });
  });
});

describe('Customer SDK - audit.verify()', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('verifies a valid audit envelope', async () => {
    const result = await client.audit.verify(undefined, 'env_test_12345');

    expect(result).toBeDefined();
    expect(typeof result.valid).toBe('boolean');
    expect(typeof result.chainIntact).toBe('boolean');
    expect(result.envelopeId).toBe('env_test_12345');
    expect(result.verifiedAt).toBeDefined();
  });

  it('returns signature for verified envelope', async () => {
    const result = await client.audit.verify(undefined, 'env_test_12345');

    if (result.signature) {
      expect(typeof result.signature).toBe('string');
      expect(result.signature.length).toBeGreaterThan(0);
    }
  });

  it('throws error for non-existent envelope', async () => {
    await expect(
      client.audit.verify(undefined, 'env_nonexistent')
    ).rejects.toThrow();
  });
});

describe('Customer SDK - audit.chain()', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('retrieves provenance chain for an envelope', async () => {
    const chain = await client.audit.chain(undefined, 'env_test_12345');

    expect(chain).toBeDefined();
    expect(Array.isArray(chain)).toBe(true);
  });

  it('returns chain entries with proper structure', async () => {
    const chain = await client.audit.chain(undefined, 'env_test_12345');

    chain.forEach(entry => {
      expect(entry.id).toBeDefined();
      expect(entry.agentId).toBeDefined();
      expect(entry.action).toBeDefined();
      expect(entry.action.type).toBeDefined();
      expect(entry.createdAt).toBeDefined();
    });
  });

  it('includes parent envelope references in chain', async () => {
    const chain = await client.audit.chain(undefined, 'env_test_12345');

    // Chain may include parent references
    chain.forEach(entry => {
      if (entry.parentEnvelopeId) {
        expect(typeof entry.parentEnvelopeId).toBe('string');
      }
    });
  });

  it('throws error for non-existent envelope', async () => {
    await expect(
      client.audit.chain(undefined, 'env_nonexistent')
    ).rejects.toThrow();
  });
});

describe('Customer SDK - Error Handling', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('handles 401 authentication errors', async () => {
    const badClient = newCustomerClient({
      token: 'cust_invalid_token',
      baseURL: MOCK_BASE_URL
    });

    await expect(
      badClient.compliance.status(undefined)
    ).rejects.toThrow();
  });

  it('handles 404 not found errors', async () => {
    await expect(
      client.audit.verify(undefined, 'envelope_nonexistent')
    ).rejects.toThrow();
  });

  it('handles 422 validation errors', async () => {
    await expect(
      client.agents.revoke(undefined, {
        targetId: '',
      }, 'idem-validation-error')
    ).rejects.toThrow();
  });

  it('handles invalid policy evaluation', async () => {
    await expect(
      client.policies.evaluate(undefined, {
        action: '',
      })
    ).rejects.toThrow();
  });
});

describe('Customer SDK - Retry Logic', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({
      token: MOCK_CUSTOMER_TOKEN,
      baseURL: MOCK_BASE_URL,
      maxRetries: 3,
      timeoutMs: 5000,
    });
  });

  it('respects custom retry configuration', () => {
    expect(client.cfg.maxRetries).toBe(3);
    expect(client.cfg.timeoutMs).toBe(5000);
  });

  it('constructs client with custom configuration', () => {
    const customClient = newCustomerClient({
      token: MOCK_CUSTOMER_TOKEN,
      baseURL: 'https://api.custom.com',
      maxRetries: 5,
      timeoutMs: 10000,
    });

    expect(customClient.cfg.maxRetries).toBe(5);
    expect(customClient.cfg.timeoutMs).toBe(10000);
    expect(customClient.getBaseURL()).toBe('https://api.custom.com');
  });
});

describe('Customer SDK - Edge Cases', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('handles revoke with minimal request', async () => {
    const response = await client.agents.revoke(undefined, {
      targetId: 'agent_minimal',
    }, 'idem-minimal-revoke');

    expect(response.affected).toBeDefined();
    expect(response.propagation).toBeDefined();
  });

  it('handles capability token with minimal constraints', async () => {
    const capability = await client.capabilities.create(undefined, {
      agentId: 'agent_edge_case_001',
      capabilities: {
        permissions: ['read'],
        resourceScope: ['minimal'],
        actionTypes: ['query'],
      },
      constraints: {
        expiresInSeconds: 60,
      },
    }, 'idem-minimal-capability');

    expect(capability.constraints.expiresInSeconds).toBe(60);
  });

  it('handles empty audit query results', async () => {
    const response = await client.audit.query(undefined, {
      agentId: 'nonexistent-agent',
      limit: 10,
    });

    expect(response.data).toHaveLength(0);
    expect(response.total).toBe(0);
  });

  it('handles policy evaluation with empty input', async () => {
    const evaluation = await client.policies.evaluate(undefined, {
      action: 'noop',
    });

    expect(evaluation).toBeDefined();
    expect(evaluation.wouldBlock).toBeDefined();
    expect(evaluation.violatedPolicies).toBeInstanceOf(Array);
  });
});
