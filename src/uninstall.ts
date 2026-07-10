/**
 * MOSS Uninstall Helper for moss-sdk-ts (npm package "moss-signing").
 *
 * Usage:
 *   node dist/uninstall.js [--dry-run]
 *
 * Local-only cleanup. Does NOT call any API or make any network request.
 */
import * as fs from 'fs';

const CONFIG_FILES = ['.moss.yml', 'moss_config.json', 'moss.config.js'];
const ENV_FILES = ['.env', '.env.local', '.env.development', '.env.production'];
const DIST_NAME = 'moss-sdk-ts';
const DEP_NAME = 'moss-signing';

export function removeConfigFiles(dryRun: boolean): string[] {
  const removed: string[] = [];
  for (const name of CONFIG_FILES) {
    if (fs.existsSync(name)) {
      console.log(dryRun ? `[DRY-RUN] Would remove: ${name}` : `Removed: ${name}`);
      if (!dryRun) fs.unlinkSync(name);
      removed.push(name);
    }
  }
  return removed;
}

export function removeEnvVars(dryRun: boolean): string[] {
  const removed: string[] = [];
  for (const name of ENV_FILES) {
    if (!fs.existsSync(name)) continue;
    const content = fs.readFileSync(name, 'utf-8');
    // Match only lines whose KEY begins with MOSS_ (preserves comments,
    // blank lines, non-MOSS keys and values that merely contain "MOSS_").
    const pattern = /^MOSS_[^=\s]*=.*$/gm;
    const matches = content.match(pattern);
    if (matches) {
      console.log(
        dryRun
          ? `[DRY-RUN] Would remove from ${name}: ${matches.length} MOSS_* vars`
          : `Removed ${matches.length} MOSS_* vars from ${name}`,
      );
      if (!dryRun) {
        const newContent = content.replace(pattern, '').replace(/\n{3,}/g, '\n\n');
        fs.writeFileSync(name, newContent);
      }
      removed.push(...matches);
    }
  }
  return removed;
}

export function removeDependency(dryRun: boolean): boolean {
  if (!fs.existsSync('package.json')) return false;
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf-8'));
  let modified = false;
  for (const section of ['dependencies', 'devDependencies', 'peerDependencies']) {
    if (pkg[section] && pkg[section][DEP_NAME]) {
      console.log(
        dryRun
          ? `[DRY-RUN] Would remove ${DEP_NAME} from ${section}`
          : `Removed ${DEP_NAME} from ${section}`,
      );
      if (!dryRun) delete pkg[section][DEP_NAME];
      modified = true;
    }
  }
  if (modified && !dryRun) {
    fs.writeFileSync('package.json', JSON.stringify(pkg, null, 2) + '\n');
  }
  return modified;
}

export function printManualChecklist(): void {
  console.log('\n' + '='.repeat(60));
  console.log('MANUAL CLEANUP CHECKLIST');
  console.log('='.repeat(60));
  console.log(`
[ ] Revoke/rotate MOSS credentials in the MOSS console
    - Revoke MOSS API keys / capability tokens
    - If agents used MOSS capability tokens, revoke those agent credentials
[ ] CI/CD: remove MOSS_API_KEY and other MOSS_* secrets from GitHub Actions / CI env
[ ] Docker: remove MOSS_* ENV lines and the MOSS dependency from Dockerfiles
[ ] Code: remove imports of ${DEP_NAME} from your source
[ ] Docs: update README / setup guides that reference MOSS
`);
}

export function main(): number {
  const dryRun = process.argv.includes('--dry-run');
  console.log(`MOSS Uninstall Helper for ${DIST_NAME}`);
  console.log('-'.repeat(40));
  if (dryRun) console.log('[DRY-RUN MODE - No changes will be made]\n');
  removeConfigFiles(dryRun);
  removeEnvVars(dryRun);
  removeDependency(dryRun);
  printManualChecklist();
  console.log(dryRun ? '\n[DRY-RUN] No changes made.' : '\nUninstall complete.');
  return 0;
}

// Only auto-run when invoked directly as a script (e.g. `node dist/uninstall.js`),
// so importing this module from tests does not terminate the test process.
if (process.argv[1] && /uninstall(\.(c|m)?[jt]s)?$/.test(process.argv[1])) {
  process.exit(main());
}
