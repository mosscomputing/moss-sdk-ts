/**
 * Mock-driven SDK unit test for moss-sdk-ts (M3 devtools).
 *
 * Starts the Prism mock server (scripts/mock.sh) against the vendored spec
 * (testdata/openapi.json) on :4010 in request-validation mode (--errors =>
 * malformed bodies => 422) with a fixed seed (m3mock) so responses are
 * byte-identical across moss-sdk-ts, moss-agent-sdk, and moss-go.
 *
 * Asserts the canonical mock contract in testdata/mock-contract.json:
 *   - Prism serves /health, a customers endpoint, the new session/introspect
 *     routes, and the compliance-report route (application/pdf) — VAL-DX-007,
 *     008, 009, 010, 019.
 *   - Prism VALIDATES request bodies: a malformed body => 422, not 200 with a
 *     canned response — VAL-DX-018.
 *   - The same vendored spec + Prism produce identical responses across repos
 *     (pinned sha256 per case) — VAL-DX-013, 014.
 *
 * Fulfills: VAL-DX-007, VAL-DX-008, VAL-DX-009, VAL-DX-010, VAL-DX-013,
 * VAL-DX-014, VAL-DX-018, VAL-DX-019.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';

const ROOT = resolve(__dirname, '..');
const CONTRACT_PATH = resolve(ROOT, 'testdata', 'mock-contract.json');
const MOCK_SCRIPT = resolve(ROOT, 'scripts', 'mock.sh');
const BASE_URL = process.env.MOSS_MOCK_URL || 'http://localhost:4010';

interface ContractCase {
  name: string;
  method: string;
  path: string;
  path_params?: Record<string, string>;
  headers?: Record<string, string>;
  body?: unknown;
  expected_status: number;
  expected_content_type_prefix: string;
  expected_sha256: string | null;
}

interface MockContract {
  base_url: string;
  customer_id: string;
  cases: ContractCase[];
}

const contract: MockContract = JSON.parse(readFileSync(CONTRACT_PATH, 'utf8'));

// ---- Prism lifecycle: start if not already running, stop if we started it. ----

let prismChild: ChildProcess | null = null;
let weStarted = false;

async function probeHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${BASE_URL}/health`, { signal: AbortSignal.timeout(1500) });
    return res.ok;
  } catch {
    return false;
  }
}

async function waitForHealth(timeoutMs = 30000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await probeHealth()) return true;
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

beforeAll(async () => {
  if (await probeHealth()) {
    weStarted = false;
    return;
  }
  // Start Prism via the repo's mock script. The script execs prism in the
  // foreground; we spawn it detached-inherit so its logs go to the test
  // process stderr.
  prismChild = spawn('bash', [MOCK_SCRIPT], {
    cwd: ROOT,
    stdio: 'inherit',
    env: { ...process.env, MOSS_MOCK_PORT: new URL(BASE_URL).port || '4010' },
  });
  weStarted = true;
  const ok = await waitForHealth(40000);
  if (!ok) {
    throw new Error(
      `mock.test.ts: Prism did not become healthy on ${BASE_URL} within 40s. ` +
        `Run 'npm run mock' in another terminal, or ensure npx can fetch @stoplight/prism-cli.`,
    );
  }
}, 120_000);

afterAll(() => {
  if (weStarted && prismChild) {
    try {
      prismChild.kill('SIGTERM');
    } catch {
      /* ignore */
    }
  }
});

// ---- HTTP helper ----

function buildPath(c: ContractCase): string {
  let p = c.path;
  if (c.path_params) {
    for (const [k, v] of Object.entries(c.path_params)) {
      p = p.replace(`{${k}}`, encodeURIComponent(v));
    }
  }
  return p;
}

async function runCase(c: ContractCase): Promise<{ status: number; contentType: string; body: Buffer }> {
  const url = `${BASE_URL}${buildPath(c)}`;
  const init: RequestInit = {
    method: c.method,
    headers: c.headers || {},
  };
  if (c.body !== undefined) {
    init.body = JSON.stringify(c.body);
    if (!(c.headers && c.headers['Content-Type'])) {
      (init.headers as Record<string, string>)['Content-Type'] = 'application/json';
    }
  }
  const res = await fetch(url, init);
  const buf = Buffer.from(await res.arrayBuffer());
  const contentType = res.headers.get('content-type') || '';
  return { status: res.status, contentType, body: buf };
}

function sha256Hex(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

describe.each(contract.cases)('Prism mock contract — $name', (c: ContractCase) => {
  it(`returns HTTP ${c.expected_status} with ${c.expected_content_type_prefix} content`, async () => {
    const { status, contentType } = await runCase(c);
    expect(status, `${c.name} status`).toBe(c.expected_status);
    expect(contentType.toLowerCase(), `${c.name} content-type`).toContain(
      c.expected_content_type_prefix.toLowerCase(),
    );
  });

  if (c.expected_sha256 !== null) {
    it('matches the pinned cross-repo sha256 (VAL-DX-014 byte-identical)', async () => {
      const { body } = await runCase(c);
      expect(sha256Hex(body), `${c.name} sha256`).toBe(c.expected_sha256);
    });
  }
});

describe('Prism mock — request-body validation (VAL-DX-018)', () => {
  it('POST /v1/partner/customers with missing required fields => 422 (not 200)', async () => {
    const { status } = await runCase(
      contract.cases.find((c) => c.name === 'customers_create_malformed')!,
    );
    expect(status).toBe(422);
  });

  it('POST /v1/tokens/introspect with missing token => 422 (not 200 {active:false})', async () => {
    const { status } = await runCase(
      contract.cases.find((c) => c.name === 'introspect_malformed')!,
    );
    expect(status).toBe(422);
  });
});

describe('Prism mock — compliance-report PDF (VAL-DX-019)', () => {
  it('returns application/pdf via Accept negotiation', async () => {
    const c = contract.cases.find((x) => x.name === 'compliance_report_pdf')!;
    const { status, contentType, body } = await runCase(c);
    expect(status).toBe(200);
    expect(contentType.toLowerCase()).toContain('application/pdf');
    expect(body.length, 'pdf body non-empty').toBeGreaterThan(0);
    expect(sha256Hex(body)).toBe(c.expected_sha256);
  });
});
