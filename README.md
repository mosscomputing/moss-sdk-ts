# @moss/sdk

TypeScript SDK for MOSS - Cryptographic signing for AI agent outputs.

**Unsigned agent output is broken output.**

[![npm](https://img.shields.io/npm/v/@moss/sdk)](https://www.npmjs.com/package/@moss/sdk)

## Installation

```bash
npm install @moss/sdk
```

## Quick Start

```typescript
import { sign, verify } from '@moss/sdk';

// Sign any agent output
const envelope = await sign({
  output: agentResponse,
  agentId: "agent-finance-01",
  context: { userId: user.id, action: "transfer" }
});

// envelope.signature: ML-DSA-44 post-quantum signature
// envelope.timestamp: Signed timestamp
// envelope.verify(): Returns true if untampered
```

## Verification

```typescript
import { verify } from '@moss/sdk';

// Verify - no network required
const result = await verify(envelope);

if (result.valid) {
  console.log(`Signed by: ${result.agentId}`);
  console.log(`At: ${new Date(envelope.timestamp * 1000)}`);
} else {
  console.log(`Invalid: ${result.reason}`);
}
```

## Using envelope.verify()

Every envelope has a built-in verify method:

```typescript
const envelope = await sign({
  output: "Transfer $50,000 to account 12345",
  agentId: "agent-finance-01"
});

// Later, verify the envelope
const result = await envelope.verify();
console.log(result.valid); // true if untampered
```

## Execution Record

Each signed output produces a verifiable execution record:

```
agent_id:      agent-finance-01
timestamp:     2026-01-18T12:34:56Z
sequence:      1
payload_hash:  SHA-256:abc123...
signature:     ML-DSA-44:xyz789...
status:        VERIFIED
```

## API

### sign(options)

Sign an agent output.

```typescript
interface SignOptions {
  output: unknown;           // The agent output to sign
  agentId: string;          // Agent identifier
  context?: Record<string, unknown>;  // Optional metadata
}

const envelope = await sign(options);
```

### verify(envelope)

Verify a signed envelope.

```typescript
const result = await verify(envelope);

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

## Features

- **Post-Quantum Security**: ML-DSA-44 (FIPS 204) signatures
- **Offline Verification**: No network required
- **Tamper Detection**: Any modification invalidates signature
- **Framework Agnostic**: Works with any AI framework
- **TypeScript Native**: Full type definitions included

## Pricing Tiers

| Tier | Price | Agents | Signatures | Retention |
|------|-------|--------|------------|-----------|
| **Free** | $0 | 5 | 1,000/day | 7 days |
| **Pro** | $1,499/mo | Unlimited | Unlimited | 1 year |
| **Enterprise** | Custom | Unlimited | Unlimited | 7 years |

*Annual billing: $1,249/mo (save $3,000/year)*

All new signups get a **14-day free trial** of Pro.

## Links

- [mosscomputing.com](https://mosscomputing.com) - Project site
- [dev.mosscomputing.com](https://dev.mosscomputing.com) - Developer Console
- [audit.mosscomputing.com](https://audit.mosscomputing.com) - Authority Vault (compliance)
- [moss-sdk (Python)](https://pypi.org/project/moss-sdk/) - Python SDK

## License

MIT - See LICENSE file.

Copyright (c) 2025 IAMPASS Inc.
