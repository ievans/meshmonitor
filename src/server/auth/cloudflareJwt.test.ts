/**
 * Cloudflare Access JWT offline verification tests.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { generateKeyPairSync, createSign, KeyObject } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyCloudflareJwt, resetCloudflareKeyCache } from './cloudflareJwt.js';

vi.mock('../../utils/logger.js', () => ({
  logger: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() }
}));

const ISSUER = 'https://team.cloudflareaccess.com';
const AUD = 'aud-tag-1';
const NOW_MS = 1_800_000_000_000;
const NOW_S = NOW_MS / 1000;

const b64 = (v: unknown) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');

function newKey() {
  return generateKeyPairSync('rsa', { modulusLength: 2048 });
}

function jwkFor(publicKey: KeyObject, kid: string) {
  return { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' };
}

function sign(privateKey: KeyObject, claims: Record<string, unknown>, headerOverride: Record<string, unknown> = {}) {
  const header = { alg: 'RS256', kid: 'k1', typ: 'JWT', ...headerOverride };
  const signingInput = `${b64(header)}.${b64(claims)}`;
  const signature = createSign('RSA-SHA256').update(signingInput).sign(privateKey).toString('base64url');
  return `${signingInput}.${signature}`;
}

const goodClaims = () => ({
  iss: ISSUER,
  aud: [AUD],
  email: 'a@example.com',
  exp: NOW_S + 3600,
  iat: NOW_S - 10
});

describe('verifyCloudflareJwt', () => {
  let dir: string;
  let jwksFile: string;
  let keyPair: ReturnType<typeof newKey>;
  const opts = () => ({ jwksFile, issuer: ISSUER, audiences: [AUD] });

  beforeEach(() => {
    resetCloudflareKeyCache();
    dir = mkdtempSync(join(tmpdir(), 'cfjwt-'));
    jwksFile = join(dir, 'certs.json');
    keyPair = newKey();
    writeFileSync(jwksFile, JSON.stringify({ keys: [jwkFor(keyPair.publicKey, 'k1')] }));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('accepts a valid token and returns its claims', () => {
    const claims = verifyCloudflareJwt(sign(keyPair.privateKey, goodClaims()), opts(), NOW_MS);
    expect(claims?.email).toBe('a@example.com');
  });

  it('accepts aud as a plain string', () => {
    const token = sign(keyPair.privateKey, { ...goodClaims(), aud: AUD });
    expect(verifyCloudflareJwt(token, opts(), NOW_MS)).not.toBeNull();
  });

  it('rejects a token signed by a different key', () => {
    const attacker = newKey();
    expect(verifyCloudflareJwt(sign(attacker.privateKey, goodClaims()), opts(), NOW_MS)).toBeNull();
  });

  it('rejects a tampered payload', () => {
    const token = sign(keyPair.privateKey, goodClaims());
    const [h, , s] = token.split('.');
    const forged = `${h}.${b64({ ...goodClaims(), email: 'admin@example.com' })}.${s}`;
    expect(verifyCloudflareJwt(forged, opts(), NOW_MS)).toBeNull();
  });

  it('rejects alg none and HS256 (algorithm confusion)', () => {
    const none = `${b64({ alg: 'none', kid: 'k1' })}.${b64(goodClaims())}.`;
    expect(verifyCloudflareJwt(none, opts(), NOW_MS)).toBeNull();
    const hs = sign(keyPair.privateKey, goodClaims(), { alg: 'HS256' });
    expect(verifyCloudflareJwt(hs, opts(), NOW_MS)).toBeNull();
  });

  it('rejects an unknown kid without trying other keys', () => {
    const token = sign(keyPair.privateKey, goodClaims(), { kid: 'other' });
    expect(verifyCloudflareJwt(token, opts(), NOW_MS)).toBeNull();
  });

  it('rejects the wrong issuer', () => {
    const token = sign(keyPair.privateKey, { ...goodClaims(), iss: 'https://evil.cloudflareaccess.com' });
    expect(verifyCloudflareJwt(token, opts(), NOW_MS)).toBeNull();
  });

  it('rejects the wrong audience (a token for another Access app)', () => {
    const token = sign(keyPair.privateKey, { ...goodClaims(), aud: ['some-other-app'] });
    expect(verifyCloudflareJwt(token, opts(), NOW_MS)).toBeNull();
  });

  it('rejects an expired token but tolerates small clock skew', () => {
    const expired = sign(keyPair.privateKey, { ...goodClaims(), exp: NOW_S - 120 });
    expect(verifyCloudflareJwt(expired, opts(), NOW_MS)).toBeNull();
    const barely = sign(keyPair.privateKey, { ...goodClaims(), exp: NOW_S - 30 });
    expect(verifyCloudflareJwt(barely, opts(), NOW_MS)).not.toBeNull();
  });

  it('rejects a token with no exp', () => {
    const { exp: _exp, ...noExp } = goodClaims();
    expect(verifyCloudflareJwt(sign(keyPair.privateKey, noExp), opts(), NOW_MS)).toBeNull();
  });

  it('rejects a token that is not valid yet', () => {
    const token = sign(keyPair.privateKey, { ...goodClaims(), nbf: NOW_S + 600 });
    expect(verifyCloudflareJwt(token, opts(), NOW_MS)).toBeNull();
  });

  it('rejects malformed tokens', () => {
    for (const bad of ['', 'a.b', 'a.b.c.d', '..', 'not-a-jwt']) {
      expect(verifyCloudflareJwt(bad, opts(), NOW_MS)).toBeNull();
    }
  });

  it('fails closed when the JWKS file is missing, empty or corrupt', () => {
    const token = sign(keyPair.privateKey, goodClaims());
    rmSync(jwksFile);
    resetCloudflareKeyCache();
    expect(verifyCloudflareJwt(token, opts(), NOW_MS)).toBeNull();

    writeFileSync(jwksFile, JSON.stringify({ keys: [] }));
    resetCloudflareKeyCache();
    expect(verifyCloudflareJwt(token, opts(), NOW_MS)).toBeNull();

    writeFileSync(jwksFile, '{not json');
    resetCloudflareKeyCache();
    expect(verifyCloudflareJwt(token, opts(), NOW_MS)).toBeNull();
  });

  it('fails closed on incomplete configuration', () => {
    const token = sign(keyPair.privateKey, goodClaims());
    expect(verifyCloudflareJwt(token, { jwksFile, issuer: '', audiences: [AUD] }, NOW_MS)).toBeNull();
    expect(verifyCloudflareJwt(token, { jwksFile, issuer: ISSUER, audiences: [] }, NOW_MS)).toBeNull();
  });

  it('picks up a rotated key file without a restart, and honours the old key until then', () => {
    const oldToken = sign(keyPair.privateKey, goodClaims());
    expect(verifyCloudflareJwt(oldToken, opts(), NOW_MS)).not.toBeNull();

    const rotated = newKey();
    writeFileSync(jwksFile, JSON.stringify({ keys: [jwkFor(rotated.publicKey, 'k2')] }));
    const later = new Date(Date.now() + 5000);
    utimesSync(jwksFile, later, later);

    expect(verifyCloudflareJwt(oldToken, opts(), NOW_MS)).toBeNull();
    const newToken = sign(rotated.privateKey, goodClaims(), { kid: 'k2' });
    expect(verifyCloudflareJwt(newToken, opts(), NOW_MS)).not.toBeNull();
  });

  it('skips a malformed key but keeps the good ones', () => {
    writeFileSync(
      jwksFile,
      JSON.stringify({ keys: [{ kty: 'RSA', kid: 'bad', n: '!!', e: 'AQAB' }, jwkFor(keyPair.publicKey, 'k1')] })
    );
    resetCloudflareKeyCache();
    expect(verifyCloudflareJwt(sign(keyPair.privateKey, goodClaims()), opts(), NOW_MS)).not.toBeNull();
  });
});
