import { createHash, timingSafeEqual } from 'node:crypto';

function bearerToken(request) {
  const authorization = request.headers.authorization ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  return match?.[1] ?? '';
}

export function authenticate(request, config) {
  if (config.authMode === 'none' || config.allowAnonymous) {
    return { ok: true, principal: 'anonymous' };
  }

  const entries = Object.entries(config.tokenHashes ?? {});
  if (entries.length === 0) {
    return {
      ok: false,
      status: 503,
      code: 'gateway_auth_not_configured',
    };
  }

  const token = bearerToken(request);
  if (!token) {
    return { ok: false, status: 401, code: 'missing_bearer_token' };
  }

  const presented = createHash('sha256').update(token, 'utf8').digest();
  let matchedPrincipal = null;

  for (const [principal, expectedHex] of entries) {
    const expected = Buffer.from(expectedHex, 'hex');
    if (expected.length === presented.length && timingSafeEqual(expected, presented)) {
      matchedPrincipal = principal;
    }
  }

  if (!matchedPrincipal) {
    return { ok: false, status: 401, code: 'invalid_bearer_token' };
  }

  return { ok: true, principal: matchedPrincipal };
}
