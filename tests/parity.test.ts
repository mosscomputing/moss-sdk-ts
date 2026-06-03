/**
 * ML-DSA-44 Parity Tests for moss-sdk-ts
 *
 * These tests verify that the TypeScript SDK uses real ML-DSA-44 (FIPS 204)
 * signing and verification — not SHA-256-padded fakes.
 *
 * Fulfills: VAL-SDK-001, VAL-SDK-002, VAL-SDK-003, VAL-SDK-004, VAL-SDK-005
 */

import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  sign,
  verify,
} from '../src/index.js';

describe('ML-DSA-44 Key Sizes (VAL-SDK-002)', () => {
  it('generates a public key of exactly 1312 bytes', async () => {
    const keyPair = await generateKeyPair();
    expect(keyPair.publicKey).toBeInstanceOf(Uint8Array);
    expect(keyPair.publicKey.length).toBe(1312);
  });

  it('generates a secret key of exactly 2560 bytes', async () => {
    const keyPair = await generateKeyPair();
    expect(keyPair.secretKey).toBeInstanceOf(Uint8Array);
    expect(keyPair.secretKey.length).toBe(2560);
  });
});

describe('ML-DSA-44 Signature Size (VAL-SDK-001)', () => {
  it('sign produces a 2420-byte ML-DSA-44 signature', async () => {
    const keyPair = await generateKeyPair();
    const payload = new TextEncoder().encode('canonical-event');
    const signature = await sign(payload, keyPair.secretKey);
    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(2420);
  });
});

describe('ML-DSA-44 Verify Accepts Honest Signature (VAL-SDK-003)', () => {
  it('verify accepts an honest signature', async () => {
    const keyPair = await generateKeyPair();
    const payload = new TextEncoder().encode('canonical-event');
    const signature = await sign(payload, keyPair.secretKey);
    const valid = await verify(payload, keyPair.publicKey, signature);
    expect(valid).toBe(true);
  });
});

describe('ML-DSA-44 Verify Rejects Bit-Flipped Signature (VAL-SDK-004)', () => {
  it('verify rejects a bit-flipped signature', async () => {
    const keyPair = await generateKeyPair();
    const payload = new TextEncoder().encode('canonical-event');
    const signature = await sign(payload, keyPair.secretKey);

    // Flip one bit in the first byte
    const tampered = new Uint8Array(signature);
    tampered[0] ^= 0x01;

    const valid = await verify(payload, keyPair.publicKey, tampered);
    expect(valid).toBe(false);
  });
});

describe('ML-DSA-44 Verify Rejects All-Zeros Signature (VAL-SDK-005)', () => {
  it('verify rejects an all-zeros 2420-byte signature', async () => {
    const keyPair = await generateKeyPair();
    const payload = new TextEncoder().encode('canonical-event');
    const zeroSignature = new Uint8Array(2420);
    const valid = await verify(payload, keyPair.publicKey, zeroSignature);
    expect(valid).toBe(false);
  });
});
