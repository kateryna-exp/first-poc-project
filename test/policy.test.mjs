import assert from 'node:assert/strict';
import test from 'node:test';
import { policyDecision } from '../src/config.mjs';

function config(mode) {
  return {
    policyMode: mode,
    policy: {
      allow: { approved: ['1.0.0'] },
      deny: { blocked: ['*'], approved: ['0.9.0'] },
    },
    custom: {
      packages: {
        custom: { versions: { '2.0.0-company.1': {} } },
      },
    },
  };
}

test('log-only mode permits upstream fallback except explicit deny rules', () => {
  assert.equal(policyDecision(config('log-only'), 'anything', '9.9.9').allowed, true);
  assert.equal(policyDecision(config('log-only'), 'blocked', '1.0.0').allowed, false);
  assert.equal(policyDecision(config('log-only'), 'approved', '0.9.0').allowed, false);
});

test('allowlist mode permits only listed versions and registered custom versions', () => {
  assert.equal(policyDecision(config('allowlist'), 'approved', '1.0.0').allowed, true);
  assert.equal(policyDecision(config('allowlist'), 'approved', '2.0.0').allowed, false);
  assert.equal(policyDecision(config('allowlist'), 'custom', '2.0.0-company.1').allowed, true);
  assert.equal(policyDecision(config('allowlist'), 'unknown', '1.0.0').allowed, false);
});
