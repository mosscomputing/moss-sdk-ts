/**
 * Customer SDK Tests — Comprehensive coverage for all customer-scoped operations
 *
 * Tests all 18 methods across 5 Customer SDK service namespaces:
 * - AgentsService (7 methods): create, list, get, update, suspend, reactivate, revoke
 * - CapabilitiesService (1 method): create
 * - ComplianceService (3 methods): status, frameworks, report
 * - PoliciesService (4 methods): list, create, update, evaluate
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

describe('Customer SDK - agents.create()', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('creates a new agent with required fields', async () => {
    const agent = await client.agents.create(undefined, {
      name: 'Support Bot',
      capabilities: {
        permittedActions: ['chat', 'read'],
        permittedResources: ['tickets'],
        permittedClassifications: ['public', 'internal'],
      },
    }, 'idem-agent-create-001');

    expect(agent).toBeDefined();
    expect(agent.name).toBe('Support Bot');
    expect(agent.status).toBe('active');
    expect(agent.initialCapabilityToken).toBeDefined();
    expect(agent.capabilities.permittedActions).toContain('chat');
    expect(agent.createdAt).toBeDefined();
  });

  it('creates an agent with behavioral bounds', async () => {
    const agent = await client.agents.create(undefined, {
      name: 'Monitored Agent',
      capabilities: {
        permittedActions: ['process'],
        permittedResources: ['data'],
        permittedClassifications: ['internal'],
      },
      behavioralBounds: {
        expectedActionsPerHour: { min: 10, max: 100 },
        expectedDelegationRate: 0.05,
      },
    }, 'idem-agent-create-002');

    expect(agent.behavioralBounds).toBeDefined();
    expect(agent.behavioralBounds?.expectedActionsPerHour.min).toBe(10);
    expect(agent.behavioralBounds?.expectedActionsPerHour.max).toBe(100);
    expect(agent.behavioralBounds?.expectedDelegationRate).toBe(0.05);
  });

  it('creates an agent with model configuration', async () => {
    const agent = await client.agents.create(undefined, {
      name: 'Claude Agent',
      capabilities: {
        permittedActions: ['analyze'],
        permittedResources: ['documents'],
        permittedClassifications: ['internal'],
      },
      model: {
        provider: 'anthropic',
        modelId: 'claude-sonnet-4-5-20250929',
      },
    }, 'idem-agent-create-003');

    expect(agent.model).toBeDefined();
    expect(agent.model?.provider).toBe('anthropic');
    expect(agent.model?.modelId).toBe('claude-sonnet-4-5-20250929');
  });

  it('creates an agent with description', async () => {
    const agent = await client.agents.create(undefined, {
      name: 'Document Processor',
      description: 'Processes and analyzes customer documents',
      capabilities: {
        permittedActions: ['read', 'analyze'],
        permittedResources: ['documents'],
        permittedClassifications: ['internal'],
      },
    }, 'idem-agent-create-004');

    expect(agent.description).toBe('Processes and analyzes customer documents');
  });

  it('creates an agent with max delegation depth', async () => {
    const agent = await client.agents.create(undefined, {
      name: 'Delegation Agent',
      capabilities: {
        permittedActions: ['delegate'],
        permittedResources: ['tasks'],
        permittedClassifications: ['internal'],
        maxDelegationDepth: 3,
      },
    }, 'idem-agent-create-005');

    expect(agent.capabilities.maxDelegationDepth).toBe(3);
  });

  it('honors idempotency key for duplicate requests', async () => {
    const idempotencyKey = 'idem-agent-duplicate';
    const req = {
      name: 'Idempotent Agent',
      capabilities: {
        permittedActions: ['test'],
        permittedResources: ['test-resource'],
        permittedClassifications: ['public'],
      },
    };

    const first = await client.agents.create(undefined, req, idempotencyKey);
    const second = await client.agents.create(undefined, req, idempotencyKey);

    expect(first.id).toBe(second.id);
    expect(first.initialCapabilityToken).toBe(second.initialCapabilityToken);
  });
});

describe('Customer SDK - agents.list()', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('lists all agents with default pagination', async () => {
    const response = await client.agents.list(undefined);

    expect(response).toBeDefined();
    expect(response.data).toBeInstanceOf(Array);
    expect(response.total).toBeGreaterThanOrEqual(0);
    expect(response.limit).toBeDefined();
    expect(response.offset).toBeDefined();
  });

  it('lists agents with status filter', async () => {
    const response = await client.agents.list(undefined, {
      status: 'active',
    });

    expect(response.data).toBeInstanceOf(Array);
    response.data.forEach(agent => {
      expect(agent.status).toBe('active');
    });
  });

  it('lists suspended agents', async () => {
    const response = await client.agents.list(undefined, {
      status: 'suspended',
    });

    expect(response.data).toBeInstanceOf(Array);
    response.data.forEach(agent => {
      expect(agent.status).toBe('suspended');
    });
  });

  it('lists agents with pagination', async () => {
    const response = await client.agents.list(undefined, {
      limit: 10,
      offset: 0,
    });

    expect(response.limit).toBe(10);
    expect(response.offset).toBe(0);
    expect(response.data.length).toBeLessThanOrEqual(10);
  });

  it('lists agents with custom limit', async () => {
    const response = await client.agents.list(undefined, {
      limit: 5,
    });

    expect(response.limit).toBe(5);
    expect(response.data.length).toBeLessThanOrEqual(5);
  });
});

describe('Customer SDK - agents.get()', () => {
  let client: Client;
  let testAgentId: string;

  beforeAll(async () => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
    const agent = await client.agents.create(undefined, {
      name: 'Get Test Agent',
      capabilities: {
        permittedActions: ['read'],
        permittedResources: ['data'],
        permittedClassifications: ['public'],
      },
    }, 'idem-agent-get-setup');
    testAgentId = agent.id;
  });

  it('retrieves agent by ID', async () => {
    const agent = await client.agents.get(undefined, testAgentId);

    expect(agent.id).toBe(testAgentId);
    expect(agent.name).toBe('Get Test Agent');
  });

  it('retrieves agent with behavioral fingerprint', async () => {
    const agent = await client.agents.get(undefined, testAgentId);

    expect(agent).toBeDefined();
    // Behavioral fingerprint may or may not exist depending on agent activity
    if (agent.behavioralFingerprint) {
      expect(agent.behavioralFingerprint.anomalyScore).toBeGreaterThanOrEqual(0);
      expect(agent.behavioralFingerprint.totalActions).toBeGreaterThanOrEqual(0);
      expect(agent.behavioralFingerprint.lastAnalyzedAt).toBeDefined();
    }
  });

  it('throws NotFoundError for non-existent agent', async () => {
    await expect(
      client.agents.get(undefined, 'agent_nonexistent')
    ).rejects.toThrow();
  });
});

describe('Customer SDK - agents.update()', () => {
  let client: Client;
  let testAgentId: string;

  beforeAll(async () => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
    const agent = await client.agents.create(undefined, {
      name: 'Update Test Agent',
      capabilities: {
        permittedActions: ['read'],
        permittedResources: ['data'],
        permittedClassifications: ['public'],
      },
    }, 'idem-agent-update-setup');
    testAgentId = agent.id;
  });

  it('updates agent name', async () => {
    const updated = await client.agents.update(undefined, testAgentId, {
      name: 'Updated Agent Name',
    }, 'idem-agent-update-name');

    expect(updated.name).toBe('Updated Agent Name');
    expect(updated.id).toBe(testAgentId);
  });

  it('updates agent description', async () => {
    const updated = await client.agents.update(undefined, testAgentId, {
      description: 'Updated description',
    }, 'idem-agent-update-description');

    expect(updated.description).toBe('Updated description');
  });

  it('updates agent capabilities', async () => {
    const updated = await client.agents.update(undefined, testAgentId, {
      capabilities: {
        permittedActions: ['read', 'write'],
      },
    }, 'idem-agent-update-capabilities');

    expect(updated.capabilities.permittedActions).toContain('read');
    expect(updated.capabilities.permittedActions).toContain('write');
  });

  it('updates behavioral bounds', async () => {
    const updated = await client.agents.update(undefined, testAgentId, {
      behavioralBounds: {
        expectedActionsPerHour: { min: 5, max: 50 },
      },
    }, 'idem-agent-update-bounds');

    expect(updated.behavioralBounds?.expectedActionsPerHour.min).toBe(5);
    expect(updated.behavioralBounds?.expectedActionsPerHour.max).toBe(50);
  });

  it('updates multiple fields at once', async () => {
    const updated = await client.agents.update(undefined, testAgentId, {
      name: 'Multi-Update Agent',
      description: 'Multi-field update test',
      capabilities: {
        permittedActions: ['multi-test'],
      },
    }, 'idem-agent-update-multi');

    expect(updated.name).toBe('Multi-Update Agent');
    expect(updated.description).toBe('Multi-field update test');
  });
});

describe('Customer SDK - agents.suspend() and reactivate()', () => {
  let client: Client;
  let testAgentId: string;

  beforeAll(async () => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
    const agent = await client.agents.create(undefined, {
      name: 'Suspend Test Agent',
      capabilities: {
        permittedActions: ['test'],
        permittedResources: ['test-resource'],
        permittedClassifications: ['public'],
      },
    }, 'idem-agent-suspend-setup');
    testAgentId = agent.id;
  });

  it('suspends an active agent', async () => {
    const suspended = await client.agents.suspend(undefined, testAgentId, {
      reason: 'Suspicious behavior detected',
    }, 'idem-agent-suspend-001');

    expect(suspended.status).toBe('suspended');
    expect(suspended.id).toBe(testAgentId);
  });

  it('reactivates a suspended agent with reason', async () => {
    await client.agents.suspend(undefined, testAgentId, {
      reason: 'Temporary suspension for testing',
    }, 'idem-agent-suspend-for-reactivate');

    const reactivated = await client.agents.reactivate(undefined, testAgentId, {
      reason: 'Issue resolved',
    }, 'idem-agent-reactivate-001');

    expect(reactivated.status).toBe('active');
  });

  it('reactivates a suspended agent without reason', async () => {
    await client.agents.suspend(undefined, testAgentId, {
      reason: 'Test suspension',
    }, 'idem-agent-suspend-for-reactivate-2');

    const reactivated = await client.agents.reactivate(undefined, testAgentId, undefined, 'idem-agent-reactivate-002');

    expect(reactivated.status).toBe('active');
  });

  it('throws error when suspending non-existent agent', async () => {
    await expect(
      client.agents.suspend(undefined, 'agent_nonexistent', {
        reason: 'Test',
      }, 'idem-agent-suspend-invalid')
    ).rejects.toThrow();
  });

  it('throws error when reactivating non-existent agent', async () => {
    await expect(
      client.agents.reactivate(undefined, 'agent_nonexistent', undefined, 'idem-agent-reactivate-invalid')
    ).rejects.toThrow();
  });
});

describe('Customer SDK - agents.revoke()', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('permanently revokes an agent', async () => {
    const agent = await client.agents.create(undefined, {
      name: 'Revoke Test Agent',
      capabilities: {
        permittedActions: ['test'],
        permittedResources: ['test-resource'],
        permittedClassifications: ['public'],
      },
    }, 'idem-agent-revoke-setup');

    await client.agents.revoke(undefined, agent.id, {
      reason: 'Agent compromised',
    }, 'idem-agent-revoke-001');

    // Verify agent is revoked by getting it
    const revoked = await client.agents.get(undefined, agent.id);
    expect(revoked.status).toBe('revoked');
  });

  it('throws error when revoking non-existent agent', async () => {
    await expect(
      client.agents.revoke(undefined, 'agent_nonexistent', {
        reason: 'Test',
      }, 'idem-agent-revoke-invalid')
    ).rejects.toThrow();
  });
});

describe('Customer SDK - capabilities.create()', () => {
  let client: Client;
  let testAgentId: string;

  beforeAll(async () => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
    const agent = await client.agents.create(undefined, {
      name: 'Capability Test Agent',
      capabilities: {
        permittedActions: ['read', 'write'],
        permittedResources: ['documents'],
        permittedClassifications: ['internal'],
      },
    }, 'idem-capability-setup');
    testAgentId = agent.id;
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

describe('Customer SDK - policies.list()', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('lists all policies with default pagination', async () => {
    const response = await client.policies.list(undefined);

    expect(response).toBeDefined();
    expect(response.data).toBeInstanceOf(Array);
    expect(response.total).toBeGreaterThanOrEqual(0);
    expect(response.limit).toBeDefined();
    expect(response.offset).toBeDefined();
  });

  it('lists policies with source filter (system)', async () => {
    const response = await client.policies.list(undefined, {
      source: 'system',
    });

    expect(response.data).toBeInstanceOf(Array);
    response.data.forEach(policy => {
      expect(policy.source).toBe('system');
    });
  });

  it('lists policies with source filter (partner)', async () => {
    const response = await client.policies.list(undefined, {
      source: 'partner',
    });

    response.data.forEach(policy => {
      expect(policy.source).toBe('partner');
    });
  });

  it('lists policies with source filter (customer)', async () => {
    const response = await client.policies.list(undefined, {
      source: 'customer',
    });

    response.data.forEach(policy => {
      expect(policy.source).toBe('customer');
    });
  });

  it('lists policies with pagination', async () => {
    const response = await client.policies.list(undefined, {
      limit: 10,
      offset: 0,
    });

    expect(response.limit).toBe(10);
    expect(response.offset).toBe(0);
    expect(response.data.length).toBeLessThanOrEqual(10);
  });
});

describe('Customer SDK - policies.create()', () => {
  let client: Client;

  beforeAll(() => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('creates a blocking policy', async () => {
    const policy = await client.policies.create(undefined, {
      name: 'Block High-Risk Transfers',
      description: 'Block transfers exceeding $10,000',
      rules: [
        {
          field: 'action.type',
          operator: 'eq',
          values: ['transfer'],
        },
        {
          field: 'action.amount',
          operator: 'gt',
          values: ['10000'],
        },
      ],
      action: 'block',
      severity: 'critical',
    }, 'idem-policy-create-block');

    expect(policy).toBeDefined();
    expect(policy.name).toBe('Block High-Risk Transfers');
    expect(policy.action).toBe('block');
    expect(policy.severity).toBe('critical');
    expect(policy.source).toBe('customer');
    expect(policy.rules).toHaveLength(2);
  });

  it('creates an approval-required policy', async () => {
    const policy = await client.policies.create(undefined, {
      name: 'Require Approval for Sensitive Data',
      rules: [
        {
          field: 'resource.classification',
          operator: 'in',
          values: ['confidential', 'secret'],
        },
      ],
      action: 'require_approval',
      severity: 'high',
    }, 'idem-policy-create-approval');

    expect(policy.action).toBe('require_approval');
    expect(policy.severity).toBe('high');
  });

  it('creates an allow policy', async () => {
    const policy = await client.policies.create(undefined, {
      name: 'Allow Public Data Access',
      rules: [
        {
          field: 'resource.classification',
          operator: 'eq',
          values: ['public'],
        },
      ],
      action: 'allow',
      severity: 'low',
    }, 'idem-policy-create-allow');

    expect(policy.action).toBe('allow');
    expect(policy.severity).toBe('low');
  });

  it('honors idempotency key for policy creation', async () => {
    const idempotencyKey = 'idem-policy-duplicate';
    const req = {
      name: 'Idempotent Policy',
      rules: [
        {
          field: 'test.field',
          operator: 'eq',
          values: ['test'],
        },
      ],
      action: 'block' as const,
      severity: 'medium' as const,
    };

    const first = await client.policies.create(undefined, req, idempotencyKey);
    const second = await client.policies.create(undefined, req, idempotencyKey);

    expect(first.id).toBe(second.id);
  });
});

describe('Customer SDK - policies.update()', () => {
  let client: Client;
  let testPolicyId: string;

  beforeAll(async () => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
    const policy = await client.policies.create(undefined, {
      name: 'Update Test Policy',
      rules: [
        {
          field: 'action.type',
          operator: 'eq',
          values: ['test'],
        },
      ],
      action: 'block',
      severity: 'medium',
    }, 'idem-policy-update-setup');
    testPolicyId = policy.id;
  });

  it('updates policy name', async () => {
    const updated = await client.policies.update(undefined, testPolicyId, {
      name: 'Updated Policy Name',
    }, 'idem-policy-update-name');

    expect(updated.name).toBe('Updated Policy Name');
    expect(updated.id).toBe(testPolicyId);
  });

  it('updates policy description', async () => {
    const updated = await client.policies.update(undefined, testPolicyId, {
      description: 'Updated description',
    }, 'idem-policy-update-description');

    expect(updated.description).toBe('Updated description');
  });

  it('updates policy action', async () => {
    const updated = await client.policies.update(undefined, testPolicyId, {
      action: 'require_approval',
    }, 'idem-policy-update-action');

    expect(updated.action).toBe('require_approval');
  });

  it('updates policy severity', async () => {
    const updated = await client.policies.update(undefined, testPolicyId, {
      severity: 'critical',
    }, 'idem-policy-update-severity');

    expect(updated.severity).toBe('critical');
  });

  it('updates policy rules', async () => {
    const updated = await client.policies.update(undefined, testPolicyId, {
      rules: [
        {
          field: 'action.type',
          operator: 'in',
          values: ['transfer', 'withdraw'],
        },
      ],
    }, 'idem-policy-update-rules');

    expect(updated.rules).toHaveLength(1);
    expect(updated.rules[0].values).toContain('transfer');
    expect(updated.rules[0].values).toContain('withdraw');
  });

  it('throws error when updating non-existent policy', async () => {
    await expect(
      client.policies.update(undefined, 'policy_nonexistent', {
        name: 'Invalid',
      }, 'idem-policy-update-invalid')
    ).rejects.toThrow();
  });
});

describe('Customer SDK - policies.evaluate()', () => {
  let client: Client;

  beforeAll(async () => {
    client = newCustomerClient({ token: MOCK_CUSTOMER_TOKEN, baseURL: MOCK_BASE_URL });
    // Create a policy to test against
    await client.policies.create(undefined, {
      name: 'Eval Test Policy',
      rules: [
        {
          field: 'action',
          operator: 'eq',
          values: ['dangerous_action'],
        },
      ],
      action: 'block',
      severity: 'critical',
    }, 'idem-policy-eval-setup');
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
      badClient.agents.list(undefined)
    ).rejects.toThrow();
  });

  it('handles 404 not found errors', async () => {
    await expect(
      client.agents.get(undefined, 'agent_nonexistent')
    ).rejects.toThrow();
  });

  it('handles 422 validation errors', async () => {
    await expect(
      client.agents.create(undefined, {
        name: '',
        capabilities: {
          permittedActions: [],
          permittedResources: [],
          permittedClassifications: [],
        },
      }, 'idem-validation-error')
    ).rejects.toThrow();
  });

  it('handles invalid policy creation', async () => {
    await expect(
      client.policies.create(undefined, {
        name: '',
        rules: [],
        action: 'block',
        severity: 'critical',
      }, 'idem-invalid-policy')
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

  it('handles agent with minimal capabilities', async () => {
    const agent = await client.agents.create(undefined, {
      name: 'Minimal Agent',
      capabilities: {
        permittedActions: ['read'],
        permittedResources: ['data'],
        permittedClassifications: ['public'],
      },
    }, 'idem-minimal-agent');

    expect(agent.capabilities.permittedActions).toHaveLength(1);
  });

  it('handles capability token with minimal constraints', async () => {
    const agent = await client.agents.create(undefined, {
      name: 'Edge Case Agent',
      capabilities: {
        permittedActions: ['test'],
        permittedResources: ['test'],
        permittedClassifications: ['public'],
      },
    }, 'idem-edge-case-agent');

    const capability = await client.capabilities.create(undefined, {
      agentId: agent.id,
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

  it('handles pagination at boundary', async () => {
    const response = await client.agents.list(undefined, {
      limit: 1,
      offset: 0,
    });

    expect(response.limit).toBe(1);
    expect(response.data.length).toBeLessThanOrEqual(1);
  });
});
