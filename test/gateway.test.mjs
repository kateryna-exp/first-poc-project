import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createGateway } from '../src/gateway.mjs';

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  return `http://127.0.0.1:${address.port}`;
}

async function close(server) {
  await new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
}

function config(upstreamBase, token, overrides = {}) {
  const upstreamRegistry = new URL(`${upstreamBase}/`);
  return {
    projectRoot: process.cwd(),
    policy: { mode: 'log-only', allow: {}, deny: {} },
    custom: { packages: {} },
    policyMode: 'log-only',
    upstreamRegistry,
    upstreamToken: '',
    allowedTarballHosts: new Set([upstreamRegistry.host]),
    publicBaseUrl: null,
    allowInsecure: true,
    tokenHashes: {
      developer: createHash('sha256').update(token).digest('hex'),
    },
    allowAnonymous: false,
    auditWebhookUrl: null,
    auditWebhookSecret: '',
    auditIpSalt: 'test-salt',
    auditIncludeUserAgent: true,
    ...overrides,
  };
}

test('calls the customizable IP hook before fetching metadata and blocks on false', async (t) => {
  let upstreamCalls = 0;
  const upstream = createServer((_request, response) => {
    upstreamCalls += 1;
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ name: 'demo-package', versions: {
      '1.0.0': { name: 'demo-package', version: '1.0.0' },
    } }));
  });
  const upstreamBase = await listen(upstream);
  t.after(() => close(upstream));

  const checkedIps = [];
  const gateway = createGateway({
    config: config(upstreamBase, 'test-token'),
    checkClientIp: async (clientIp) => {
      checkedIps.push(clientIp);
      return clientIp !== '198.51.100.10';
    },
    auditEmitter: async () => {},
  });
  const server = createServer(gateway);
  const base = await listen(server);
  t.after(() => close(server));

  const request = (ip) => fetch(`${base}/demo-package`, {
    headers: { authorization: 'Bearer test-token', 'x-forwarded-for': ip },
  });
  const allowed = await request('198.51.100.9');
  assert.equal(allowed.status, 200);
  assert.equal(allowed.headers.get('cdn-cache-control'), 'private, no-store');
  const blocked = await request('198.51.100.10');
  assert.equal(blocked.status, 403);
  assert.equal((await blocked.json()).error, 'client_ip_not_allowed');
  assert.deepEqual(checkedIps, ['198.51.100.9', '198.51.100.10']);
  assert.equal(upstreamCalls, 1);
});

test('serves upstream tarball URLs directly and retains gateway tarball support', async (t) => {
  const tarball = Buffer.from('mock npm tarball bytes');
  const integrity = `sha512-${createHash('sha512').update(tarball).digest('base64')}`;
  let upstreamBase = '';
  const upstream = createServer((request, response) => {
    if (request.url === '/demo-package') {
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({
        name: 'demo-package',
        'dist-tags': { latest: '1.0.0' },
        versions: {
          '1.0.0': {
            name: 'demo-package',
            version: '1.0.0',
            dist: {
              tarball: `${upstreamBase}/demo-package/-/demo-package-1.0.0.tgz`,
              integrity,
            },
          },
        },
      }));
      return;
    }
    if (request.url === '/demo-package/-/demo-package-1.0.0.tgz') {
      response.setHeader('content-type', 'application/octet-stream');
      response.setHeader('content-length', String(tarball.length));
      response.end(request.method === 'HEAD' ? undefined : tarball);
      return;
    }
    response.statusCode = 404;
    response.end();
  });
  upstreamBase = await listen(upstream);
  t.after(() => close(upstream));

  const events = [];
  const token = 'test-token';
  const gateway = createGateway({
    config: config(upstreamBase, token),
    auditEmitter: async (_config, _fetch, event) => events.push(event),
  });
  const gatewayServer = createServer((request, response) => gateway(request, response));
  const gatewayBase = await listen(gatewayServer);
  t.after(() => close(gatewayServer));

  const headers = { authorization: `Bearer ${token}` };
  const metadataResponse = await fetch(`${gatewayBase}/npm/demo-package`, { headers });
  assert.equal(metadataResponse.status, 200);
  const metadata = await metadataResponse.json();
  const rewrittenTarball = metadata.versions['1.0.0'].dist.tarball;
  assert.equal(rewrittenTarball, `${upstreamBase}/demo-package/-/demo-package-1.0.0.tgz`);

  const tarballResponse = await fetch(rewrittenTarball, { headers });
  assert.equal(tarballResponse.status, 200);
  assert.deepEqual(Buffer.from(await tarballResponse.arrayBuffer()), tarball);
  const conventionalTarballResponse = await fetch(
    `${gatewayBase}/demo-package/-/demo-package-1.0.0.tgz`,
    { headers },
  );
  assert.equal(conventionalTarballResponse.status, 200);
  assert.deepEqual(Buffer.from(await conventionalTarballResponse.arrayBuffer()), tarball);
  assert.equal(events.find((event) => event.action === 'package_metadata')?.principal, 'developer');
  const download = events.find((event) => event.action === 'tarball_download');
  assert.equal(download.version, '1.0.0');
  assert.equal(download.integrityVerified, true);
});

test('overrides only the registered version and keeps other upstream versions', async (t) => {
  const customBytes = Buffer.from('custom preloader 1.0.0');
  const root = await mkdtemp(path.join(tmpdir(), 'gateway-custom-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'packages'));
  await writeFile(path.join(root, 'packages', 'preloader-1.0.0.tgz'), customBytes);

  let upstreamBase;
  const upstream = createServer((request, response) => {
    assert.equal(request.url, '/preloader');
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({
      name: 'preloader',
      'dist-tags': { latest: '2.0.0' },
      versions: {
        '1.0.0': { version: '1.0.0', dist: { tarball: `${upstreamBase}/preloader/-/preloader-1.0.0.tgz` } },
        '2.0.0': { version: '2.0.0', dist: { tarball: `${upstreamBase}/preloader/-/preloader-2.0.0.tgz` } },
      },
    }));
  });
  upstreamBase = await listen(upstream);
  t.after(() => close(upstream));

  const gateway = createGateway({
    config: config(upstreamBase, 'test-token', {
      projectRoot: root,
      custom: { packages: {
        preloader: {
          replaceUpstream: false,
          distTags: { company: '1.0.0' },
          versions: {
            '1.0.0': {
              file: 'packages/preloader-1.0.0.tgz',
              manifest: { name: 'preloader', version: '1.0.0' },
              integrity: `sha512-${createHash('sha512').update(customBytes).digest('base64')}`,
              shasum: createHash('sha1').update(customBytes).digest('hex'),
            },
          },
        },
      } },
    }),
    auditEmitter: async () => {},
  });
  const gatewayServer = createServer((request, response) => gateway(request, response));
  const gatewayBase = await listen(gatewayServer);
  t.after(() => close(gatewayServer));

  const headers = { authorization: 'Bearer test-token' };
  const response = await fetch(`${gatewayBase}/preloader`, { headers });
  assert.equal(response.status, 200);
  const metadata = await response.json();
  assert.deepEqual(Object.keys(metadata.versions).sort(), ['1.0.0', '2.0.0']);
  assert.equal(metadata['dist-tags'].latest, '2.0.0');
  assert.equal(metadata.versions['2.0.0'].dist.tarball, `${upstreamBase}/preloader/-/preloader-2.0.0.tgz`);
  assert.match(metadata.versions['1.0.0'].dist.tarball, new RegExp(`^${gatewayBase}/-/tarballs/`));
  const tarball = await fetch(metadata.versions['1.0.0'].dist.tarball, { headers });
  assert.equal(tarball.status, 200);
  assert.deepEqual(Buffer.from(await tarball.arrayBuffer()), customBytes);
});

test('forwards npm security audit requests and records the result', async (t) => {
  const events = [];
  const upstream = createServer(async (request, response) => {
    assert.equal(request.url, '/-/npm/v1/security/advisories/bulk');
    assert.equal(request.method, 'POST');
    assert.deepEqual(JSON.parse(Buffer.concat(await Array.fromAsync(request)).toString()), { demo: ['1.0.0'] });
    response.setHeader('content-type', 'application/json');
    response.end('{}');
  });
  const upstreamBase = await listen(upstream);
  t.after(() => close(upstream));
  const token = 'test-token';
  const gateway = createGateway({
    config: config(upstreamBase, token),
    auditEmitter: async (_config, _fetch, event) => events.push(event),
  });
  const gatewayServer = createServer((request, response) => gateway(request, response));
  const gatewayBase = await listen(gatewayServer);
  t.after(() => close(gatewayServer));
  const result = await fetch(`${gatewayBase}/-/npm/v1/security/advisories/bulk`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ demo: ['1.0.0'] }),
  });
  assert.equal(result.status, 200);
  assert.deepEqual(await result.json(), {});
  assert.equal(events.find((event) => event.action === 'npm_security_audit')?.result, 'success');
});

test('rejects unauthenticated and denylisted package requests', async (t) => {
  const upstream = createServer((_request, response) => {
    response.statusCode = 500;
    response.end();
  });
  const upstreamBase = await listen(upstream);
  t.after(() => close(upstream));
  const token = 'test-token';
  const gateway = createGateway({
    config: config(upstreamBase, token, {
      policy: { mode: 'log-only', allow: {}, deny: { blocked: ['*'] } },
    }),
    auditEmitter: async () => {},
  });
  const gatewayServer = createServer((request, response) => gateway(request, response));
  const gatewayBase = await listen(gatewayServer);
  t.after(() => close(gatewayServer));

  assert.equal((await fetch(`${gatewayBase}/npm/demo-package`)).status, 401);
  assert.equal((await fetch(`${gatewayBase}/npm/blocked`, {
    headers: { authorization: `Bearer ${token}` },
  })).status, 403);
});
