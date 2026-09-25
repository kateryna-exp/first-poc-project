import assert from 'node:assert/strict';
import test from 'node:test';
import { dependenciesFromLockfile } from '../scripts/report-lockfile.mjs';

test('extracts unique unscoped and scoped dependencies from lockfile v3', () => {
  const dependencies = dependenciesFromLockfile({
    lockfileVersion: 3,
    packages: {
      '': { name: 'app', version: '1.0.0' },
      'node_modules/alpha': { version: '1.2.3' },
      'node_modules/@scope/tool': { version: '4.5.6' },
      'node_modules/parent/node_modules/alpha': { version: '1.2.3' },
    },
  });
  assert.deepEqual(dependencies, [
    { name: '@scope/tool', version: '4.5.6' },
    { name: 'alpha', version: '1.2.3' },
  ]);
});
