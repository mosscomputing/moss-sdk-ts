/**
 * Behavior tests for the moss-sdk-ts uninstall helper.
 *
 * Fulfills: VAL-TSSDK-B01..B10
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  removeConfigFiles,
  removeEnvVars,
  removeDependency,
  main,
} from '../src/uninstall.js';

const ENV_CONTENT = [
  '# MOSS configuration',
  'MOSS_API_KEY=secret-key',
  'MOSS_TRUST_URL=https://trust.example.com',
  'NOT_MOSS_KEY=keepme',
  'OTHER=MOSS_value',
  '',
  'DATABASE_URL=postgres://localhost/app',
].join('\n') + '\n';

const PKG_CONTENT = JSON.stringify(
  {
    name: 'consumer-app',
    version: '1.0.0',
    dependencies: { 'moss-signing': '^0.1.0', express: '^4.18.0' },
    devDependencies: { 'moss-signing': '^0.1.0', vitest: '^1.0.0' },
    peerDependencies: { 'moss-signing': '^0.1.0' },
  },
  null,
  2,
) + '\n';

let tmpDir: string;
let originalCwd: string;

function seedFixture(): void {
  fs.writeFileSync('.moss.yml', 'org: acme\n');
  fs.writeFileSync('moss_config.json', '{"api":"x"}\n');
  fs.writeFileSync('moss.config.js', 'module.exports = {};\n');
  fs.writeFileSync('.env', ENV_CONTENT);
  fs.writeFileSync('package.json', PKG_CONTENT);
  fs.writeFileSync('README.md', '# Consumer App\n');
  fs.mkdirSync('subdir');
  fs.writeFileSync(path.join('subdir', '.env'), 'MOSS_API_KEY=nested\n');
}

beforeEach(() => {
  originalCwd = process.cwd();
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'moss-uninstall-'));
  process.chdir(tmpDir);
});

afterEach(() => {
  process.chdir(originalCwd);
  fs.rmSync(tmpDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe('config file removal (VAL-TSSDK-B01)', () => {
  it('removes MOSS config files on a real run', () => {
    seedFixture();
    const removed = removeConfigFiles(false);
    expect(removed.sort()).toEqual(['.moss.yml', 'moss.config.js', 'moss_config.json']);
    expect(fs.existsSync('.moss.yml')).toBe(false);
    expect(fs.existsSync('moss_config.json')).toBe(false);
    expect(fs.existsSync('moss.config.js')).toBe(false);
  });
});

describe('env var stripping (VAL-TSSDK-B02, B09)', () => {
  it('removes only MOSS_-keyed lines, preserving everything else', () => {
    seedFixture();
    removeEnvVars(false);
    const after = fs.readFileSync('.env', 'utf-8');
    expect(after).not.toMatch(/^MOSS_API_KEY=/m);
    expect(after).not.toMatch(/^MOSS_TRUST_URL=/m);
    // Preserved: comment, non-MOSS key, value that merely contains MOSS_, blank-derived spacing, other keys.
    expect(after).toContain('# MOSS configuration');
    expect(after).toContain('NOT_MOSS_KEY=keepme');
    expect(after).toContain('OTHER=MOSS_value');
    expect(after).toContain('DATABASE_URL=postgres://localhost/app');
  });

  it('does not recurse into subdirectories', () => {
    seedFixture();
    removeEnvVars(false);
    expect(fs.readFileSync(path.join('subdir', '.env'), 'utf-8')).toBe('MOSS_API_KEY=nested\n');
  });
});

describe('dependency removal + manifest validity (VAL-TSSDK-B03, B08)', () => {
  it('removes moss-signing from all dep sections, keeping JSON valid and other deps intact', () => {
    seedFixture();
    const changed = removeDependency(false);
    expect(changed).toBe(true);
    const pkg = JSON.parse(fs.readFileSync('package.json', 'utf-8'));
    expect(pkg.dependencies['moss-signing']).toBeUndefined();
    expect(pkg.devDependencies['moss-signing']).toBeUndefined();
    expect(pkg.peerDependencies['moss-signing']).toBeUndefined();
    expect(pkg.dependencies.express).toBe('^4.18.0');
    expect(pkg.devDependencies.vitest).toBe('^1.0.0');
    expect(pkg.name).toBe('consumer-app');
  });
});

describe('--dry-run makes no changes (VAL-TSSDK-B04)', () => {
  it('reports intended actions but mutates nothing', () => {
    seedFixture();
    const before = fs.readFileSync('.env', 'utf-8');
    const pkgBefore = fs.readFileSync('package.json', 'utf-8');

    removeConfigFiles(true);
    removeEnvVars(true);
    removeDependency(true);

    expect(fs.existsSync('.moss.yml')).toBe(true);
    expect(fs.existsSync('moss_config.json')).toBe(true);
    expect(fs.existsSync('moss.config.js')).toBe(true);
    expect(fs.readFileSync('.env', 'utf-8')).toBe(before);
    expect(fs.readFileSync('package.json', 'utf-8')).toBe(pkgBefore);
  });
});

describe('checklist + exit 0 (VAL-TSSDK-B05)', () => {
  it('prints the manual cleanup checklist and returns 0', () => {
    seedFixture();
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const argv = process.argv;
    process.argv = ['node', 'uninstall-test'];
    try {
      const code = main();
      expect(code).toBe(0);
    } finally {
      process.argv = argv;
    }
    const output = log.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(output).toContain('MANUAL CLEANUP CHECKLIST');
    expect(output).toContain('Revoke/rotate MOSS credentials');
    expect(output).toContain('Uninstall complete.');
  });
});

describe('idempotent no-op when nothing to clean (VAL-TSSDK-B06)', () => {
  it('runs cleanly in an empty dir, creates no files, returns 0', () => {
    const argv = process.argv;
    process.argv = ['node', 'uninstall-test'];
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    try {
      expect(main()).toBe(0);
    } finally {
      process.argv = argv;
    }
    expect(fs.readdirSync('.')).toEqual([]);
  });
});

describe('does not touch unrelated files (VAL-TSSDK-B07)', () => {
  it('leaves unrelated files byte-identical after a real run', () => {
    seedFixture();
    const readmeBefore = fs.readFileSync('README.md');
    const argv = process.argv;
    process.argv = ['node', 'uninstall-test'];
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
    try {
      main();
    } finally {
      process.argv = argv;
    }
    expect(fs.readFileSync('README.md')).toEqual(readmeBefore);
    expect(fs.existsSync('README.md')).toBe(true);
  });
});

describe('dry-run / real action parity (VAL-TSSDK-B10)', () => {
  it('the dry-run plan matches the real run actions', () => {
    seedFixture();
    const dryConfig = removeConfigFiles(true);
    const dryEnv = removeEnvVars(true);
    const dryDep = removeDependency(true);
    // Nothing changed during dry-run.
    expect(fs.existsSync('.moss.yml')).toBe(true);

    const realConfig = removeConfigFiles(false);
    const realEnv = removeEnvVars(false);
    const realDep = removeDependency(false);

    expect(dryConfig).toEqual(realConfig);
    expect(dryEnv).toEqual(realEnv);
    expect(dryDep).toEqual(realDep);
  });
});
