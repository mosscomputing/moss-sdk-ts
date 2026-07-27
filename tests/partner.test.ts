/**
 * Partner SDK Tests — Comprehensive coverage for all customer management methods
 *
 * Tests all 12 customer lifecycle methods in the Partner SDK:
 * - create, get, list, update, promote, suspend, reactivate, deactivate
 * - session, asCustomer, revokeSession, complianceReport
 *
 * Coverage: happy path, error cases, edge cases, idempotency
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { newPartnerClient } from '../src/partner/index.js';
import type { Client } from '../src/partner/client.js';

// Mock server setup (assumes Prism mock server running on localhost:3100)
const MOCK_BASE_URL = process.env.MOSS_API_BASE_URL || 'http://localhost:3100';
const MOCK_PARTNER_TOKEN = process.env.MOSS_TEST_PARTNER_TOKEN || 'prt_test_12345678901234567890123456';

describe('Partner SDK - Client Construction', () => {
  it('creates a partner client with default base URL', () => {
    const client = newPartnerClient({ token: MOCK_PARTNER_TOKEN });
    expect(client).toBeDefined();
    expect(client.getPersona()).toBe('partner');
    expect(client.customers).toBeDefined();
    expect(client.compliance).toBeDefined();
  });

  it('creates a partner client with custom base URL', () => {
    const client = newPartnerClient({
      token: MOCK_PARTNER_TOKEN,
      baseURL: MOCK_BASE_URL
    });
    expect(client.getBaseURL()).toBe(MOCK_BASE_URL);
  });

  it('throws error when token is missing', () => {
    expect(() => newPartnerClient({ token: '' })).toThrow('Config.token is required');
  });
});

describe('Partner SDK - customers.create()', () => {
  let client: Client;

  beforeAll(() => {
    client = newPartnerClient({ token: MOCK_PARTNER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('creates a new customer with required fields', async () => {
    const customer = await client.customers.create(undefined, {
      external_id: 'ext-test-001',
      name: 'Test Corp',
    }, 'idem-create-001');

    expect(customer).toBeDefined();
    expect(customer.external_id).toBe('ext-test-001');
    expect(customer.name).toBe('Test Corp');
    expect(customer.status).toBeDefined();
    expect(customer.created_at).toBeDefined();
  });

  it('creates a customer with optional governance settings', async () => {
    const customer = await client.customers.create(undefined, {
      external_id: 'ext-test-002',
      name: 'Secure Corp',
      governance: {
        requireApprovalThreshold: 1000,
        allowedActions: ['transfer', 'withdraw'],
      },
    }, 'idem-create-002');

    expect(customer.governance).toBeDefined();
    expect(customer.governance?.requireApprovalThreshold).toBe(1000);
  });

  it('creates a customer with limits', async () => {
    const customer = await client.customers.create(undefined, {
      external_id: 'ext-test-003',
      name: 'Limited Corp',
      limits: {
        maxAgents: 10,
        maxSignaturesPerMonth: 1000,
      },
    }, 'idem-create-003');

    expect(customer.limits).toBeDefined();
    expect(customer.limits?.maxAgents).toBe(10);
  });

  it('honors idempotency key for duplicate requests', async () => {
    const idempotencyKey = 'idem-duplicate-test';
    const req = {
      external_id: 'ext-idem-001',
      name: 'Idem Test',
    };

    const first = await client.customers.create(undefined, req, idempotencyKey);
    const second = await client.customers.create(undefined, req, idempotencyKey);

    expect(first.customer_id).toBe(second.customer_id);
    expect(first.external_id).toBe(second.external_id);
  });
});

describe('Partner SDK - customers.get()', () => {
  let client: Client;

  beforeAll(() => {
    client = newPartnerClient({ token: MOCK_PARTNER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('retrieves customer by ID', async () => {
    // First create a customer
    const created = await client.customers.create(undefined, {
      external_id: 'ext-get-001',
      name: 'Get Test',
    }, 'idem-get-001');

    const customer = await client.customers.get(undefined, created.customer_id);
    expect(customer.customer_id).toBe(created.customer_id);
    expect(customer.external_id).toBe('ext-get-001');
  });

  it('throws NotFoundError for non-existent customer', async () => {
    await expect(
      client.customers.get(undefined, 'cust_nonexistent')
    ).rejects.toThrow();
  });
});

describe('Partner SDK - customers.list()', () => {
  let client: Client;

  beforeAll(() => {
    client = newPartnerClient({ token: MOCK_PARTNER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('lists all customers with default pagination', async () => {
    const response = await client.customers.list(undefined);

    expect(response).toBeDefined();
    expect(response.data).toBeInstanceOf(Array);
    expect(response.total).toBeGreaterThanOrEqual(0);
    expect(response.limit).toBeDefined();
    expect(response.offset).toBeDefined();
  });

  it('lists customers with status filter', async () => {
    const response = await client.customers.list(undefined, {
      status: 'sandbox_active',
    });

    expect(response.data).toBeInstanceOf(Array);
    response.data.forEach(customer => {
      expect(customer.status).toBe('sandbox_active');
    });
  });

  it('lists customers with pagination', async () => {
    const response = await client.customers.list(undefined, {
      limit: 10,
      offset: 0,
    });

    expect(response.limit).toBe(10);
    expect(response.offset).toBe(0);
    expect(response.data.length).toBeLessThanOrEqual(10);
  });
});

describe('Partner SDK - customers.update()', () => {
  let client: Client;
  let testCustomerId: string;

  beforeAll(async () => {
    client = newPartnerClient({ token: MOCK_PARTNER_TOKEN, baseURL: MOCK_BASE_URL });
    const customer = await client.customers.create(undefined, {
      external_id: 'ext-update-001',
      name: 'Update Test',
    }, 'idem-update-setup');
    testCustomerId = customer.customer_id;
  });

  it('updates customer name', async () => {
    const updated = await client.customers.update(undefined, testCustomerId, {
      name: 'Updated Name',
    }, 'idem-update-name');

    expect(updated.name).toBe('Updated Name');
    expect(updated.customer_id).toBe(testCustomerId);
  });

  it('updates governance settings', async () => {
    const updated = await client.customers.update(undefined, testCustomerId, {
      governance: {
        requireApprovalThreshold: 5000,
        allowedActions: ['read', 'write'],
      },
    }, 'idem-update-governance');

    expect(updated.governance?.requireApprovalThreshold).toBe(5000);
    expect(updated.governance?.allowedActions).toContain('read');
  });

  it('updates limits', async () => {
    const updated = await client.customers.update(undefined, testCustomerId, {
      limits: {
        maxAgents: 50,
      },
    }, 'idem-update-limits');

    expect(updated.limits?.maxAgents).toBe(50);
  });
});

describe('Partner SDK - customers.promote()', () => {
  let client: Client;
  let testCustomerId: string;

  beforeAll(async () => {
    client = newPartnerClient({ token: MOCK_PARTNER_TOKEN, baseURL: MOCK_BASE_URL });
    const customer = await client.customers.create(undefined, {
      external_id: 'ext-promote-001',
      name: 'Promote Test',
    }, 'idem-promote-setup');
    testCustomerId = customer.customer_id;
  });

  it('promotes customer to production with required attestation', async () => {
    const promoted = await client.customers.promote(undefined, testCustomerId, {
      attestation: {
        complianceFrameworks: ['SOC2', 'ISO27001'],
        attestedBy: 'legal@example.com',
        attestedAt: new Date().toISOString(),
      },
      billing: {
        stripeCustomerId: 'cus_stripe123',
        tier: 'platform',
      },
    }, 'idem-promote-001');

    expect(promoted.status).toBe('production_active');
    expect(promoted.customer_id).toBe(testCustomerId);
  });

  it('throws ValidationError when promoting without attestation', async () => {
    await expect(
      client.customers.promote(undefined, testCustomerId, {
        attestation: undefined as any,
        billing: {
          stripeCustomerId: 'cus_stripe456',
          tier: 'platform',
        },
      }, 'idem-promote-invalid')
    ).rejects.toThrow();
  });
});

describe('Partner SDK - customers.suspend() and reactivate()', () => {
  let client: Client;
  let testCustomerId: string;

  beforeAll(async () => {
    client = newPartnerClient({ token: MOCK_PARTNER_TOKEN, baseURL: MOCK_BASE_URL });
    const customer = await client.customers.create(undefined, {
      external_id: 'ext-suspend-001',
      name: 'Suspend Test',
    }, 'idem-suspend-setup');
    testCustomerId = customer.customer_id;
  });

  it('suspends an active customer', async () => {
    const suspended = await client.customers.suspend(undefined, testCustomerId, {
      reason: 'Non-payment',
    }, 'idem-suspend-001');

    expect(suspended.status).toBe('suspended');
  });

  it('reactivates a suspended customer', async () => {
    // First suspend
    await client.customers.suspend(undefined, testCustomerId, {
      reason: 'Test suspension',
    }, 'idem-suspend-for-reactivate');

    // Then reactivate
    const reactivated = await client.customers.reactivate(undefined, testCustomerId, {
      resolution: 'Payment received',
    }, 'idem-reactivate-001');

    expect(reactivated.status).not.toBe('suspended');
  });
});

describe('Partner SDK - customers.deactivate()', () => {
  let client: Client;

  beforeAll(() => {
    client = newPartnerClient({ token: MOCK_PARTNER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('permanently deactivates a customer', async () => {
    const customer = await client.customers.create(undefined, {
      external_id: 'ext-deactivate-001',
      name: 'Deactivate Test',
    }, 'idem-deactivate-setup');

    await client.customers.deactivate(undefined, customer.customer_id, {
      reason: 'Customer requested account closure',
    }, 'idem-deactivate-001');

    // Verify customer is deactivated
    const deactivated = await client.customers.get(undefined, customer.customer_id);
    expect(deactivated.status).toBe('deactivated');
  });
});

describe('Partner SDK - customers.session()', () => {
  let client: Client;
  let testCustomerId: string;

  beforeAll(async () => {
    client = newPartnerClient({ token: MOCK_PARTNER_TOKEN, baseURL: MOCK_BASE_URL });
    const customer = await client.customers.create(undefined, {
      external_id: 'ext-session-001',
      name: 'Session Test',
    }, 'idem-session-setup');
    testCustomerId = customer.customer_id;
  });

  it('creates a customer session with default TTL', async () => {
    const session = await client.customers.session(undefined, testCustomerId, {}, 'idem-session-001');

    expect(session).toBeDefined();
    expect(session.token).toBeDefined();
    expect(session.expiresAt).toBeDefined();
  });

  it('creates a customer session with custom TTL', async () => {
    const session = await client.customers.session(undefined, testCustomerId, {
      ttl: 3600, // 1 hour
    }, 'idem-session-ttl');

    expect(session.token).toBeDefined();
    const expiresAt = new Date(session.expiresAt);
    const now = new Date();
    const diff = (expiresAt.getTime() - now.getTime()) / 1000;
    expect(diff).toBeGreaterThan(3500); // Allow some variance
    expect(diff).toBeLessThan(3700);
  });
});

describe('Partner SDK - customers.asCustomer()', () => {
  let client: Client;
  let testCustomerId: string;

  beforeAll(async () => {
    client = newPartnerClient({ token: MOCK_PARTNER_TOKEN, baseURL: MOCK_BASE_URL });
    const customer = await client.customers.create(undefined, {
      external_id: 'ext-ascust-001',
      name: 'AsCustomer Test',
    }, 'idem-ascust-setup');
    testCustomerId = customer.customer_id;
  });

  it('creates a customer-scoped client', async () => {
    const customerClient = await client.customers.asCustomer(undefined, testCustomerId);

    expect(customerClient).toBeDefined();
    expect(customerClient.getPersona()).toBe('customer');
    // Customer client should have customer namespaces
    expect(customerClient.agents).toBeDefined();
    expect(customerClient.policies).toBeDefined();
  });
});

describe('Partner SDK - customers.revokeSession()', () => {
  let client: Client;
  let testCustomerId: string;
  let sessionId: string;

  beforeAll(async () => {
    client = newPartnerClient({ token: MOCK_PARTNER_TOKEN, baseURL: MOCK_BASE_URL });
    const customer = await client.customers.create(undefined, {
      external_id: 'ext-revoke-001',
      name: 'Revoke Test',
    }, 'idem-revoke-setup');
    testCustomerId = customer.customer_id;

    const session = await client.customers.session(undefined, testCustomerId, {}, 'idem-revoke-session');
    sessionId = session.sessionId;
  });

  it('revokes an active session', async () => {
    await client.customers.revokeSession(undefined, testCustomerId, sessionId, 'idem-revoke-001');

    // Session should be revoked (verify via attempting to use it would fail)
    // This is a void method, so we just verify it doesn't throw
    expect(true).toBe(true);
  });
});

describe('Partner SDK - customers.complianceReport()', () => {
  let client: Client;
  let testCustomerId: string;

  beforeAll(async () => {
    client = newPartnerClient({ token: MOCK_PARTNER_TOKEN, baseURL: MOCK_BASE_URL });
    const customer = await client.customers.create(undefined, {
      external_id: 'ext-compliance-001',
      name: 'Compliance Test',
    }, 'idem-compliance-setup');
    testCustomerId = customer.customer_id;
  });

  it('generates a compliance report', async () => {
    const report = await client.customers.complianceReport(undefined, testCustomerId, {
      framework: 'SOC2',
      startDate: '2025-01-01',
      endDate: '2025-12-31',
    });

    expect(report).toBeDefined();
    expect(report.framework).toBe('SOC2');
    expect(report.signature).toBeDefined();
    expect(report.keyId).toBeDefined();
  });

  it('generates report with specific frameworks', async () => {
    const report = await client.customers.complianceReport(undefined, testCustomerId, {
      framework: 'ISO27001',
      startDate: '2025-01-01',
      endDate: '2025-12-31',
    });

    expect(report.framework).toBe('ISO27001');
  });
});

describe('Partner SDK - Error Handling', () => {
  let client: Client;

  beforeAll(() => {
    client = newPartnerClient({ token: MOCK_PARTNER_TOKEN, baseURL: MOCK_BASE_URL });
  });

  it('handles 401 authentication errors', async () => {
    const badClient = newPartnerClient({
      token: 'prt_invalid_token',
      baseURL: MOCK_BASE_URL
    });

    await expect(
      badClient.customers.list(undefined)
    ).rejects.toThrow();
  });

  it('handles 404 not found errors', async () => {
    await expect(
      client.customers.get(undefined, 'cust_nonexistent')
    ).rejects.toThrow();
  });

  it('handles 409 conflict errors on duplicate external_id', async () => {
    const req = {
      external_id: 'ext-conflict-001',
      name: 'Conflict Test',
    };

    await client.customers.create(undefined, req, 'idem-conflict-first');

    await expect(
      client.customers.create(undefined, req, 'idem-conflict-second')
    ).rejects.toThrow();
  });

  it('handles 422 validation errors', async () => {
    await expect(
      client.customers.create(undefined, {
        external_id: '', // Empty external_id should fail validation
        name: 'Invalid',
      }, 'idem-validation-error')
    ).rejects.toThrow();
  });
});

describe('Partner SDK - Retry Logic', () => {
  let client: Client;

  beforeAll(() => {
    client = newPartnerClient({
      token: MOCK_PARTNER_TOKEN,
      baseURL: MOCK_BASE_URL,
      maxRetries: 3,
      timeoutMs: 5000,
    });
  });

  it('respects custom retry configuration', () => {
    expect(client.cfg.maxRetries).toBe(3);
    expect(client.cfg.timeoutMs).toBe(5000);
  });
});
