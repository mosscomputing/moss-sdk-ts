# Dependabot Vulnerability Remediation Plan

## Status: 2026-08-22

### Fixed (3 of 9)

| Package | Was | Now | Method | Advisory |
|---------|-----|-----|--------|----------|
| lodash | 4.17.21 (nested in postman-collection) | 4.18.1 | npm override | GHSA-r5fr-rjxr-66jc, GHSA-f23m-r3pf-42rh, GHSA-xxjr-mmjv-4gpg |
| uuid | 8.3.2 (nested in postman-collection) | 11.1.1 | npm override | GHSA-w5hq-g745-h8pq |
| esbuild | 0.27.3 (transitive via tsup) | 0.28.2 | npm override | GHSA-g7r4-m6w7-qqqr |

All three overrides are API-compatible with their parent packages:
- `postman-collection` uses `uuid.v4()` (named export unchanged in uuid 11.x)
- `lodash` 4.18.1 is a patch release within the same major version
- `esbuild` 0.27->0.28 has no breaking API changes for tsup's usage

Build, TypeScript, and tests all pass with the overrides applied.

### Remaining (6)

All 6 remaining vulnerabilities are in transitive dependencies of `@stoplight/prism-cli` (dev-only, NOT shipped in the npm package). They cannot be fixed via simple npm overrides because the patched versions require major version jumps that break the parent package's API.

#### 1. js-yaml (HIGH) - GHSA-5p4m-2wfm-xmqj

- **Vulnerable version:** 3.15.1 (nested in `json-schema-ref-parser@6.1.0`)
- **Patched version:** 4.1.0 (but 4.x removed `safeLoad`/`safeDump`)
- **Parent usage:** `json-schema-ref-parser` calls `yaml.safeLoad()` and `yaml.safeDump()` which were renamed to `load`/`dump` in js-yaml 4.x
- **Why override breaks:** `safeLoad`/`safeDump` do not exist in js-yaml 4.x, causing a runtime TypeError
- **Plan:** Replace `json-schema-ref-parser@6.1.0` with `@apidevtools/json-schema-ref-parser` (maintained fork that supports js-yaml 4.x), OR upgrade `@stoplight/prism-cli` to a version that uses the newer ref-parser. Investigate prism-cli 5.16.0's dependency tree.
- **Timeline:** Next sprint
- **Risk if unfixed:** Dev-only. DoS via malicious YAML in OpenAPI spec during mock testing. Not exploitable in production.

#### 2. nanoid (HIGH) - GHSA-2v37-7h3g-55p8

- **Vulnerable version:** 3.3.18 (nested in `postcss@8.5.23` via `tsup@8.5.1`)
- **Patched version:** 5.0.9+ (but 4.x+ is ESM-only)
- **Parent usage:** `postcss` uses `require('nanoid')` (CJS import). nanoid 4.x+ is ESM-only.
- **Why override breaks:** `require('nanoid')` returns an empty object for ESM-only packages in CJS context. postcss would crash on every build.
- **Plan:** Wait for `postcss` to publish a version that supports nanoid 5.x (or is ESM-native). Alternatively, upgrade `tsup` to a version that uses a postcss version with the fix. Check tsup 9.x roadmap.
- **Timeline:** When postcss or tsup ships a compatible version
- **Risk if unfixed:** Dev-only. Infinite loop when nanoid custom generator is called with size=0. Not exploitable in production (postcss generates IDs with non-zero size).

#### 3. fast-uri (HIGH) - host confusion via backslash authority introducer

- **Vulnerable version:** 3.1.5 (nested in `ajv@8.20.0` via `@stoplight/prism-http@5.12.0`)
- **Patched version:** 4.1.2 (major version jump, no patch in 3.x)
- **Parent usage:** `ajv` uses `fast-uri` for URI resolution in JSON schema validation. ajv declares `^3.0.1` which excludes 4.x.
- **Why override may break:** fast-uri 4.x may have API changes. Need to verify that ajv 8.20.0's usage of fast-uri (primarily `resolve()` and `serialize()` functions) is compatible with 4.x API.
- **Plan:** Test fast-uri 4.x override in isolation. If ajv's usage is compatible, apply override. If not, upgrade ajv to a version that supports fast-uri 4.x (check ajv 9.x). If ajv 9.x is not available, fork/patch ajv or replace with a different validator.
- **Timeline:** Next sprint (requires testing)
- **Risk if unfixed:** Dev-only. URI host confusion in JSON schema validation during mock testing. Not exploitable in production.

#### 4. fast-xml-parser (MODERATE) - XML Comment and CDATA Injection

- **Vulnerable version:** 4.5.7 (direct dep of `@stoplight/prism-http-server@5.12.2`)
- **Patched version:** 5.7.0+ (but 5.x is a major version jump)
- **Parent usage:** `prism-http-server` uses `new XMLBuilder({})` from fast-xml-parser 4.x. Need to verify if `XMLBuilder` exists in 5.x with the same constructor options.
- **Why override may break:** fast-xml-parser 5.x may have changed the XMLBuilder API, constructor options, or export structure.
- **Plan:** Test fast-xml-parser 5.x override in isolation. If `XMLBuilder` API is compatible, apply override. If not, upgrade `@stoplight/prism-cli` to a version using fast-xml-parser 5.x, or replace prism with a different mock server.
- **Timeline:** Next sprint (requires testing)
- **Risk if unfixed:** Dev-only. XML injection in mock server responses. Not exploitable in production.

#### 5. brace-expansion (HIGH) - via eslint/minimatch

- **Vulnerable version:** 5.0.8 (nested in `minimatch@10.2.5` via `eslint@10.8.0`)
- **Patched version:** Need to check if a patched version exists in the 5.x range
- **Plan:** Check if brace-expansion has a patched 5.x release. If so, apply override. If not, upgrade eslint to a version with a patched minimatch.
- **Timeline:** Next sprint
- **Risk if unfixed:** Dev-only. ReDoS via malicious glob pattern in linting config. Not exploitable in production.

#### 6. @stoplight/prism-cli (MODERATE) - aggregate of above

- This is not a direct vulnerability but an aggregate entry for the transitive deps above. Fixing the individual vulnerabilities will resolve this.

### Summary

| Category | Count | Status |
|----------|-------|--------|
| Fixed via npm overrides | 3 | Done, build passes |
| Requires dependency replacement/upgrade | 3 | Planned for next sprint |
| Requires waiting for upstream fix | 1 (nanoid/postcss) | Blocked on upstream |
| Requires investigation | 2 (fast-uri, fast-xml-parser) | Planned for next sprint |

All remaining vulnerabilities are in **dev-only dependencies** (mock testing, linting, building) and are **not shipped in the published npm package** (`moss-signing`). The `files` field in package.json only includes `dist/`, so none of these vulnerable packages reach end users.
