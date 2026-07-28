# Changelog

All notable changes to moss-sdk-ts will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-28

### Added

- **Partner SDK** - Complete customer lifecycle management API for SaaS partners
  - Customer CRUD operations (create, get, list, update)
  - Lifecycle management (promote, suspend, reactivate, deactivate)
  - Session management (session, asCustomer, revokeSession)
  - Compliance reporting (complianceReport with PDF/JSON export)
  - Portal URL generation for white-label embedding
- **Customer SDK** - Agent governance API for end customers
  - Agent registration and management
  - Capability token issuance with scoped permissions
  - Compliance status checking and framework verification
  - Policy management (list, create, evaluate)
  - Audit trail querying and envelope verification
- **Comprehensive test suite** - 100% coverage for all SDK methods
  - Partner SDK tests: 12 customer lifecycle methods
  - Customer SDK tests: agents, capabilities, compliance, policies, audit
  - Agent SDK tests: ML-DSA-44 signing and verification
  - Fixture-based tests with shared test corpus
  - Mock server tests with Prism validation

### Security

- **Fixed 2 ReDoS vulnerabilities** (CVE TBD) in Partner SDK
  - `src/partner/client.ts:124` - Replaced polynomial regex `/\/+$/` with safe O(n) while-loop on user-controlled `baseURL`
  - `src/partner/portalurl.ts:53` - Replaced polynomial regex `/\/+$/` with safe O(n) while-loop on `opts.portalBase`
  - **Impact**: Prevented catastrophic backtracking DoS attacks via malicious URLs with thousands of trailing slashes
  - **Root cause**: Using `/pattern+$/` regex on untrusted input
  - **Fix**: Replaced with `while (str.endsWith('/')) { str = str.slice(0, -1); }` pattern
  - **Credit**: GitHub Advanced Security CodeQL analysis

### Changed

- Package name updated to `moss-signing` for consistency with Python/Go SDKs
- Export structure now supports three entry points:
  - `moss-signing` - Agent SDK (ML-DSA-44 signing)
  - `moss-signing/partner` - Partner SDK (customer management)
  - `moss-signing/customer` - Customer SDK (agent governance)

## [0.1.1] - 2026-06-18

### Added

- Initial release with ML-DSA-44 post-quantum signature support
- Agent SDK with envelope signing and verification
- Enterprise features (certification, handshake)
- TypeScript type definitions

## [0.1.0] - 2026-06-01

### Added

- Initial development release
- ML-DSA-44 cryptographic primitives via @noble/post-quantum
- Basic envelope structure (spec: moss-0001)

---

[0.2.0]: https://github.com/mosscomputing/moss-sdk-ts/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/mosscomputing/moss-sdk-ts/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mosscomputing/moss-sdk-ts/releases/tag/v0.1.0
