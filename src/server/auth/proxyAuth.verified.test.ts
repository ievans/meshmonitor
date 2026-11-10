/**
 * proxyAuth with PROXY_AUTH_CF_JWKS_FILE set: only a verified Cloudflare JWT
 * yields an identity, and the unauthenticated proxy headers are ignored.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { generateKeyPairSync, createSign, KeyObject } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Request } from 'express';
import { extractProxyUser } from './proxyAuth.js';
import { resetCloudflareKeyCache } from './cloudflareJwt.js';

const ISSUER = 'https://team.cloudflareaccess.com';
const AUD = 'aud-tag-1';

let mockConfig: Record<string, unknown>;

vi.mock('../config/environment.js', () => ({
  getEnvironmentConfig: () => mockConfig
}));
vi.mock('../../utils/logger.js', () => ({
  logger: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() }
}));

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');

function sign(privateKey: KeyObject, claims: Record<string, unknown>) {
  const input = `${b64({ alg: 'RS256', kid: 'k1' })}.${b64(claims)}`;
  return `${input}.${createSign('RSA-SHA256').update(input).sign(privateKey).toString('base64url')}`;
}

const reqWith = (headers: Record<string, string>) => ({ headers }) as unknown as Request;
const claims = (extra: Record<string, unknown> = {}) => ({
  iss: ISSUER,
  aud: [AUD],
  email: 'a@example.com',
  groups: ['mesh-admins'],
  exp: Math.floor(Date.now() / 1000) + 3600,
  ...extra
});

describe('proxyAuth with Cloudflare JWT verification', () => {
  let dir: string;
  let keys: ReturnType<typeof generateKeyPairSync>;

  beforeEach(() => {
    resetCloudflareKeyCache();
    dir = mkdtempSync(join(tmpdir(), 'pa-'));
    keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const file = join(dir, 'certs.json');
    writeFileSync(file, JSON.stringify({ keys: [{ ...keys.publicKey.export({ format: 'jwk' }), kid: 'k1' }] }));
    mockConfig = {
      proxyAuthEnabled: true,
      proxyAuthJwtGroupsClaim: 'groups',
      proxyAuthCfJwksFile: file,
      proxyAuthCfIssuer: ISSUER,
      proxyAuthCfAudiences: [AUD]
    };
  });

  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('returns the user and groups from a verified token', () => {
    const user = extractProxyUser(reqWith({ 'cf-access-jwt-assertion': sign(keys.privateKey, claims()) }));
    expect(user).toEqual({ email: 'a@example.com', groups: ['mesh-admins'], source: 'cloudflare' });
  });

  it('rejects a forged token (right shape, attacker key)', () => {
    const attacker = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const user = extractProxyUser(reqWith({ 'cf-access-jwt-assertion': sign(attacker.privateKey, claims()) }));
    expect(user).toBeNull();
  });

  it('does not fall back to other headers when the JWT is bad', () => {
    const attacker = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const user = extractProxyUser(
      reqWith({
        'cf-access-jwt-assertion': sign(attacker.privateKey, claims()),
        'x-auth-request-email': 'admin@example.com',
        'remote-user': 'admin@example.com'
      })
    );
    expect(user).toBeNull();
  });

  it('ignores identity headers entirely when there is no JWT', () => {
    expect(extractProxyUser(reqWith({ 'x-auth-request-email': 'admin@example.com' }))).toBeNull();
    expect(extractProxyUser(reqWith({ 'remote-user': 'admin@example.com' }))).toBeNull();
  });

  it('rejects everything when verification is half-configured', () => {
    mockConfig.proxyAuthCfAudiences = [];
    expect(extractProxyUser(reqWith({ 'cf-access-jwt-assertion': sign(keys.privateKey, claims()) }))).toBeNull();
  });

  it('keeps the legacy unverified behaviour when no JWKS file is configured', () => {
    mockConfig.proxyAuthCfJwksFile = undefined;
    const attacker = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const user = extractProxyUser(reqWith({ 'cf-access-jwt-assertion': sign(attacker.privateKey, claims()) }));
    expect(user?.email).toBe('a@example.com');
  });
});
