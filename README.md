# @moss/sdk

TypeScript SDK for MOSS - Cryptographic signing for AI agent outputs.

**Unsigned agent output is broken output.**

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

const result = await verify(envelope);

if (result.valid) {
  console.log(`Signed by: ${result.agentId}`);
  console.log(`At: ${new Date(envelope.timestamp * 1000)}`);
} else {
  console.log(`⚠️ Signature invalid: ${result.reason}`);
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

## Security

MOSS uses ML-DSA-44 (Dilithium) for post-quantum secure signatures:

- Resistant to quantum computer attacks
- NIST FIPS 204 standardized
- ~2.4KB signatures
- Fast verification

## License

MIT - See LICENSE file.

Copyright (c) 2025 IAMPASS Inc.
