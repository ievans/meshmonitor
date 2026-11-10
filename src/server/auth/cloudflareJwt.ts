/**
 * Offline verification of Cloudflare Access JWTs (`Cf-Access-Jwt-Assertion`).
 *
 * The signing keys are read from a local JWKS file (the response of
 * `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`) that something
 * outside this process refreshes, so MeshMonitor needs no network path to
 * Cloudflare. Every failure returns null: callers must treat that as "no
 * identity", never fall back to unverified headers.
 *
 * Checks: RS256 only, signature against the key whose `kid` matches, `iss`,
 * `aud`, `exp` (required) and `nbf`.
 */

import { createPublicKey, createVerify, KeyObject } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { logger } from '../../utils/logger.js';

/** Clock skew tolerated on exp/nbf, in seconds. */
const CLOCK_SKEW_SECONDS = 60;

export interface CloudflareJwtOptions {
  /** Path to the JWKS file. */
  jwksFile: string;
  /** Expected `iss`, e.g. `https://<team>.cloudflareaccess.com`. */
  issuer: string;
  /** Accepted `aud` values (the Access application AUD tags). */
  audiences: string[];
}

interface KeyCache {
  file: string;
  mtimeMs: number;
  keys: Map<string, KeyObject>;
}

let cache: KeyCache | null = null;

/** Test hook: forget cached keys. */
export function resetCloudflareKeyCache(): void {
  cache = null;
}

function loadKeys(file: string): Map<string, KeyObject> | null {
  try {
    const mtimeMs = statSync(file).mtimeMs;
    if (cache && cache.file === file && cache.mtimeMs === mtimeMs) {
      return cache.keys;
    }
    const parsed = JSON.parse(readFileSync(file, 'utf8'));
    const keys = new Map<string, KeyObject>();
    for (const jwk of Array.isArray(parsed?.keys) ? parsed.keys : []) {
      if (jwk?.kty !== 'RSA' || typeof jwk.kid !== 'string' || !jwk.kid) continue;
      try {
        keys.set(jwk.kid, createPublicKey({ key: jwk, format: 'jwk' }));
      } catch {
        // A malformed key must not take the good ones down with it.
        logger.warn(`Skipping unusable key in Cloudflare JWKS file (kid ${jwk.kid})`);
      }
    }
    if (keys.size === 0) {
      logger.error('Cloudflare JWKS file contains no usable RSA keys; rejecting all proxy logins');
      cache = null;
      return null;
    }
    cache = { file, mtimeMs, keys };
    return keys;
  } catch (err) {
    cache = null;
    logger.error('Cannot read Cloudflare JWKS file; rejecting all proxy logins:', err);
    return null;
  }
}

function decodePart(part: string): Record<string, unknown> | null {
  try {
    const value = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

/**
 * Verify a Cloudflare Access JWT and return its claims, or null if it is not
 * valid for this deployment.
 */
export function verifyCloudflareJwt(
  token: string,
  options: CloudflareJwtOptions,
  nowMs: number = Date.now()
): Record<string, unknown> | null {
  if (!options.jwksFile || !options.issuer || options.audiences.length === 0) {
    logger.error('Cloudflare JWT verification is enabled but PROXY_AUTH_CF_* is incomplete; rejecting');
    return null;
  }

  const parts = token.split('.');
  if (parts.length !== 3 || parts.some(p => p.length === 0)) return null;
  const [headerPart, payloadPart, signaturePart] = parts;

  const header = decodePart(headerPart);
  if (!header || header.alg !== 'RS256' || typeof header.kid !== 'string') return null;

  const keys = loadKeys(options.jwksFile);
  const key = keys?.get(header.kid);
  if (!key) return null;

  try {
    const verifier = createVerify('RSA-SHA256');
    verifier.update(`${headerPart}.${payloadPart}`);
    if (!verifier.verify(key, Buffer.from(signaturePart, 'base64url'))) return null;
  } catch {
    return null;
  }

  const claims = decodePart(payloadPart);
  if (!claims) return null;

  if (claims.iss !== options.issuer) return null;

  const aud: unknown[] = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.some(a => typeof a === 'string' && options.audiences.includes(a))) return null;

  const nowSeconds = Math.floor(nowMs / 1000);
  if (typeof claims.exp !== 'number' || claims.exp + CLOCK_SKEW_SECONDS < nowSeconds) return null;
  if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || claims.nbf - CLOCK_SKEW_SECONDS > nowSeconds)) {
    return null;
  }

  return claims;
}
