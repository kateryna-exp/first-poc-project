import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { authenticate } from '../src/auth.mjs';

function request(token = '') {
  return { headers: token ? { authorization: `Bearer ${token}` } : {} };
}

test('authenticates a token by SHA-256 hash without storing plaintext', () => {
  const token = 'developer-secret';
  const digest = createHash('sha256').update(token).digest('hex');
  const config = { allowAnonymous: false, tokenHashes: { 'developer-a': digest } };
  assert.deepEqual(authenticate(request(token), config), {
    ok: true,
    principal: 'developer-a',
  });
  assert.equal(authenticate(request('wrong'), config).code, 'invalid_bearer_token');
  assert.equal(authenticate(request(), config).code, 'missing_bearer_token');
});

test('fails closed when no token hashes are configured', () => {
  const result = authenticate(request('anything'), { allowAnonymous: false, tokenHashes: {} });
  assert.equal(result.status, 503);
  assert.equal(result.code, 'gateway_auth_not_configured');
});
