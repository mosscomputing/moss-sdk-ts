# moss-sdk-ts

MOSS SDK for TypeScript - cryptographic signing for AI agent actions.

[![npm](https://img.shields.io/npm/v/@moss/sdk)](https://www.npmjs.com/package/@moss/sdk)

## Overview

MOSS provides cryptographic signing for AI agent outputs using ML-DSA-44, a post-quantum digital signature algorithm standardized in NIST FIPS 204. Every agent action is signed to create non-repudiable execution records with audit-grade provenance. Unsigned agent output is broken output.

### ML-DSA-44 Parameter Sizes (FIPS 204)

| Parameter | Size |
|-----------|------|
| Public Key | 1312 bytes |
| Secret Key | 2560 bytes |
| Signature | 2420 bytes |

## Installation

```bash
npm install moss-signing
```

## Usage

The SDK provides three entry points for different use cases:

### Partner SDK

For SaaS partners managing customer lifecycle and compliance.

```typescript
import { newPartnerClient } from 'moss-signing/partner';

const partner = newPartnerClient({
  token: process.env.MOSS_PARTNER_KEY,
});

// Create customer
const customer = await partner.customers.create({
  externalId: 'acme_123',
  name: 'Acme Corp',
  email: 'admin@acme.com',
});

console.log(customer.id);  // cust_xxx
console.log(customer.sandboxToken);  // For customer to use

// List customers
const customers = await partner.customers.list({ limit: 100 });

// Promote to production
const promoted = await partner.customers.promote('cust_xxx', {
  attestation: {
    kycCompleted: true,
    termsAccepted: true,
  },
});

// Get compliance report
const report = await partner.customers.complianceReport('cust_xxx', {
  format: 'pdf',
});
```

### Customer SDK

For end customers managing AI agents and governance.

```typescript
import { newCustomerClient } from 'moss-signing/customer';

const customer = newCustomerClient({
  token: process.env.MOSS_CUSTOMER_KEY,
});

// Register an agent
const agent = await customer.agents.create({
  name: 'Customer Support Bot',
  capabilities: {
    permittedActions: ['chat', 'search'],
    permittedResources: ['customer_data'],
  },
});

console.log(agent.id);  // agent_001
console.log(agent.initialCapabilityToken);  // For runtime

// Issue capability token
const token = await customer.capabilities.create({
  agentId: 'agent_001',
  capabilities: {
    permissions: ['read:customer_data'],
  },
  constraints: {
    executionLimit: 10,
    expiresInSeconds: 300,
  },
});

// Check compliance status
const compliance = await customer.compliance.status();
console.log(`Score: ${compliance.score}`);

// Create policy
const policy = await customer.policies.create({
  name: 'Block competitor mentions',
  rules: [
    { field: 'output', operator: 'contains', values: ['CompetitorX'] },
  ],
  action: 'block',
});

// Query audit trail
const logs = await customer.audit.query({
  agentId: 'agent_001',
  startTime: '2026-07-01T00:00:00Z',
  limit: 100,
});
```

### Agent SDK

For AI agents signing actions with ML-DSA-44.

```typescript
import { generateKeyPair, sign, verify } from 'moss-signing';

// Generate a keypair
const keyPair = await generateKeyPair();

// Sign a payload
const payload = new TextEncoder().encode('agent action output');
const signature = await sign(payload, keyPair.secretKey);

// Verify - no network required
const valid = await verify(payload, keyPair.publicKey, signature);
console.log(valid); // true
```

## Features

- **Cryptographic signing (ML-DSA-44)** - Post-quantum secure signatures per NIST FIPS 204
- **Policy evaluation** - Server-side policy checks with allow/block/hold decisions
- **Evidence chain linking** - Sequential signatures with payload hashes for audit trails
- **Offline verification** - Verify signatures locally without network calls

## API Reference

### generateKeyPair()

Generate a new ML-DSA-44 keypair.

```typescript
const keyPair = await generateKeyPair();
// keyPair.publicKey: Uint8Array (1312 bytes)
// keyPair.secretKey: Uint8Array (2560 bytes)
```

### sign(payload, secretKey)

Sign a message with ML-DSA-44.

```typescript
const signature = await sign(payload, keyPair.secretKey);
// signature: Uint8Array (2420 bytes)
```

### verify(payload, publicKey, signature)

Verify a signature with ML-DSA-44.

```typescript
const valid = await verify(payload, keyPair.publicKey, signature);
// valid: boolean
```

### signEnvelope(options)

Sign an agent output and produce a cryptographic envelope.

```typescript
interface SignOptions {
  output: unknown;           // The agent output to sign
  agentId: string;          // Agent identifier
  context?: Record<string, unknown>;  // Optional metadata
}

const envelope = await signEnvelope(options);
```

### verifyEnvelope(envelope)

Verify a signed envelope.

```typescript
const result = await verifyEnvelope(envelope);

interface VerifyResult {
  valid: boolean;           // True if signature is valid
  subject?: string;         // The agent that signed
  agentId?: string;         // Alias for subject
  payloadHash?: string;     // Hash of signed payload
  reason?: string;          // Error reason if invalid
}
```

### Envelope

The signed envelope contains:

```typescript
interface Envelope {
  spec: string;            // Protocol version ("moss-0001")
  version: number;         // Format version
  alg: string;             // Algorithm ("ML-DSA-44")
  subject: string;         // Agent identifier
  keyVersion: number;      // Key version for rotation
  seq: number;             // Sequence number
  issuedAt: number;        // Unix timestamp
  payloadHash: string;     // SHA-256 hash of payload
  signature: string;       // Base64URL encoded signature
  
  // Convenience
  agentId: string;         // Alias for subject
  timestamp: number;       // Alias for issuedAt
  verify(): Promise<VerifyResult>;
}
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `MOSS_API_KEY` | API key for enterprise features | None |
| `MOSS_API_URL` | Custom API endpoint | `https://api.mosscomputing.com` |

## Links

- Documentation: [docs.mosscomputing.com/sdks/typescript](https://docs.mosscomputing.com/sdks/typescript)
- Dashboard: [app.mosscomputing.com](https://app.mosscomputing.com)
- Python SDK: [pypi.org/project/moss-sdk](https://pypi.org/project/moss-sdk/)

## License

Business Source License 1.1 - See LICENSE file.

Copyright (c) 2025-2026 IAMPASS Inc.
