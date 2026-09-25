import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { gunzipSync, gzipSync } from 'node:zlib';
import test from 'node:test';
import { createGateway } from '../src/gateway.mjs';

const execute = promisify(execFile);

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

function writeField(header, offset, length, value) {
  Buffer.from(value).copy(header, offset, 0, length);
}

function tarEntry(name, content) {
  const bytes = Buffer.from(content);
  const header = Buffer.alloc(512);
  writeField(header, 0, 100, name);
  writeField(header, 100, 8, '0000644\0');
  writeField(header, 108, 8, '0000000\0');
  writeField(header, 116, 8, '0000000\0');
  writeField(header, 124, 12, `${bytes.length.toString(8).padStart(11, '0')}\0`);
  writeField(header, 136, 12, '00000000000\0');
  header.fill(0x20, 148, 156);
  header[156] = '0'.charCodeAt(0);
  writeField(header, 257, 6, 'ustar\0');
  writeField(header, 263, 2, '00');
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  writeField(header, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `);
  const padding = Buffer.alloc((512 - (bytes.length % 512)) % 512);
  return Buffer.concat([header, bytes, padding]);
}

function packageTarball() {
  return gzipSync(Buffer.concat([
    tarEntry('package/package.json', JSON.stringify({
      name: 'demo-package',
      version: '1.0.0',
      main: 'index.js',
    })),
    tarEntry('package/index.js', "module.exports = 'installed-through-gateway';\n"),
    Buffer.alloc(1024),
  ]));
}

test('a real npm client uses gateway metadata and direct upstream tarballs', { timeout: 30_000 }, async (t) => {
  const tarball = packageTarball();
  const integrity = `sha512-${createHash('sha512').update(tarball).digest('base64')}`;
  const shasum = createHash('sha1').update(tarball).digest('hex');
  let upstreamBase = '';
  const upstream = createServer((request, response) => {
    if (request.url === '/-/npm/v1/security/advisories/bulk') {
      (async () => {
        assert.equal(request.headers['content-encoding'], 'gzip');
        const bytes = Buffer.concat(await Array.fromAsync(request));
        assert.deepEqual(JSON.parse(gunzipSync(bytes).toString()), { 'demo-package': ['1.0.0'] });
        response.setHeader('content-type', 'application/json');
        response.end('{}');
      })().catch((error) => {
        response.statusCode = 500;
        response.end(error.message);
      });
      return;
    }
    if (request.url === '/demo-package') {
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({
        name: 'demo-package',
        'dist-tags': { latest: '1.0.0' },
        versions: {
          '1.0.0': {
            name: 'demo-package',
            version: '1.0.0',
            main: 'index.js',
            dist: {
              tarball: `${upstreamBase}/demo-package/-/demo-package-1.0.0.tgz`,
              integrity,
              shasum,
            },
          },
        },
      }));
      return;
    }
    if (request.url === '/demo-package/-/demo-package-1.0.0.tgz') {
      response.setHeader('content-type', 'application/octet-stream');
      response.setHeader('content-length', String(tarball.length));
      response.end(tarball);
      return;
    }
    response.statusCode = 404;
    response.end();
  });
  upstreamBase = await listen(upstream);
  t.after(() => close(upstream));

  const token = 'npm-client-token';
  const upstreamUrl = new URL(`${upstreamBase}/`);
  const events = [];
  const gateway = createGateway({
    config: {
      projectRoot: process.cwd(),
      policy: { mode: 'log-only', allow: {}, deny: {} },
      custom: { packages: {} },
      policyMode: 'log-only',
      upstreamRegistry: upstreamUrl,
      upstreamToken: '',
      allowedTarballHosts: new Set([upstreamUrl.host]),
      publicBaseUrl: null,
      allowInsecure: true,
      tokenHashes: {
        'npm-client': createHash('sha256').update(token).digest('hex'),
      },
      allowAnonymous: false,
      auditWebhookUrl: null,
      auditWebhookSecret: '',
      auditIpSalt: '',
      auditIncludeUserAgent: true,
    },
    auditEmitter: async (_config, _fetch, event) => events.push(event),
  });
  const gatewayServer = createServer((request, response) => gateway(request, response));
  const gatewayBase = await listen(gatewayServer);
  t.after(() => close(gatewayServer));

  const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'npm-gateway-test-'));
  t.after(() => rm(temporaryDirectory, { recursive: true, force: true }));
  const gatewayHost = new URL(gatewayBase).host;
  await writeFile(path.join(temporaryDirectory, 'package.json'), JSON.stringify({
    name: 'gateway-consumer-test',
    version: '1.0.0',
    private: true,
    dependencies: { 'demo-package': '1.0.0' },
  }, null, 2));
  await writeFile(path.join(temporaryDirectory, '.npmrc'), [
    `registry=${gatewayBase}/npm/`,
    `//${gatewayHost}/npm/:_authToken=${token}`,
    'replace-registry-host=never',
    'audit=true',
    'fund=true',
    '',
  ].join('\n'));

  const npmExecutable = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const installResult = await execute(npmExecutable, ['install', '--ignore-scripts'], {
    cwd: temporaryDirectory,
    env: {
      ...process.env,
      NPM_CONFIG_AUDIT: 'true',
      NPM_CONFIG_FUND: 'true',
      npm_config_cache: path.join(temporaryDirectory, 'npm-cache'),
      NO_PROXY: '127.0.0.1,localhost',
      no_proxy: '127.0.0.1,localhost',
    },
    timeout: 20_000,
  });
  assert.match(installResult.stdout, /audited \d+ packages?/);
  assert.match(installResult.stdout, /found 0 vulnerabilities/);
  assert.equal(events.some((event) => event.action === 'npm_security_audit' && event.result === 'success'), true);

  const installed = await readFile(path.join(temporaryDirectory, 'node_modules/demo-package/index.js'), 'utf8');
  assert.match(installed, /installed-through-gateway/);
  const lockfile = JSON.parse(await readFile(path.join(temporaryDirectory, 'package-lock.json'), 'utf8'));
  assert.equal(lockfile.packages['node_modules/demo-package'].resolved, `${upstreamBase}/demo-package/-/demo-package-1.0.0.tgz`);
  assert.equal(events.some((event) => event.action === 'package_metadata' && event.principal === 'npm-client'), true);
  assert.equal(events.some((event) => event.action === 'tarball_download'), false);

  await execute(npmExecutable, ['audit', '--json'], {
    cwd: temporaryDirectory,
    env: {
      ...process.env,
      npm_config_cache: path.join(temporaryDirectory, 'npm-cache'),
      NO_PROXY: '127.0.0.1,localhost',
      no_proxy: '127.0.0.1,localhost',
    },
    timeout: 20_000,
  });
  assert.equal(events.some((event) => event.action === 'npm_security_audit' && event.result === 'success'), true);
});
