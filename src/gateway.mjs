import { createHash } from 'node:crypto'; 
import { createReadStream, statSync } from 'node:fs';

import { pipeline } from 'node:stream/promises';

import {

  getCustomPackage,

  getCustomVersion,

  loadConfig,

  permittedUpstreamVersions,

  policyDecision,

  resolveCustomTarball,

} from './config.mjs';

import { authenticate } from './auth.mjs';

import { emitAudit, requestContext } from './audit.mjs';

import {

  copyResponseHeaders,

  readBody,

  streamFetchBody,

  writeJson,

} from './http.mjs';


const INSTALL_V1 = 'application/vnd.npm.install-v1+json';
// Normal upstream tarballs are downloaded directly from the registry.
// Registered custom packages continue to use the gateway.

const AUDIT_ENDPOINTS = new Set([

  '-/npm/v1/security/advisories/bulk',

  '-/npm/v1/security/audits/quick',

]);


class GatewayError extends Error {

  constructor(status, code, detail = '') {

    super(detail || code);

    this.status = status;

    this.code = code;

  }

}


function safeDecode(value) {

  try {

    return decodeURIComponent(value);

  } catch {

    throw new GatewayError(400, 'invalid_url_encoding');

  }

}


function registryPath(request) {

  const parsed = new URL(request.url ?? '/', 'http://gateway.local');

  const rewritten = parsed.searchParams.get('path');

  const raw = rewritten !== null

    ? rewritten

    : parsed.pathname.startsWith('/npm/')

      ? parsed.pathname.slice('/npm/'.length)

      : parsed.pathname.replace(/^\/api\/registry\/?/, '');

  return safeDecode(raw.replace(/^\/+/, ''));

}


function validPackageName(name) {

  if (typeof name !== 'string' || name.length < 1 || name.length > 214) return false;

  if (name.startsWith('.') || name.includes('\\') || /[\u0000-\u0020\u007f]/.test(name)) return false;

  if (name.startsWith('@')) {

    return /^@[a-z0-9._\~-]+\/[a-z0-9._\~-]+$/i.test(name);

  }

  return /^[a-z0-9_\~][a-z0-9._\~-]*$/i.test(name);

}


function validVersion(version) {

  return typeof version === 'string'

    && version.length >= 1

    && version.length <= 128

    && /^[0-9a-z][0-9a-z.+_-]*$/i.test(version);

}


function upstreamHeaders(config, request, contentType = '') {

  const headers = {

    accept: INSTALL_V1,

    'accept-encoding': 'identity',

    'user-agent': 'company-npm-gateway/1.0',

  };

  if (contentType) headers['content-type'] = contentType;

  if (config.upstreamToken) headers.authorization = `Bearer ${config.upstreamToken}`;

  return headers;

}


function assertSafeUpstreamUrl(config, value, allowedHosts) {

  const url = value instanceof URL ? value : new URL(value);

  if (url.username || url.password) {

    throw new GatewayError(502, 'upstream_url_contains_credentials');

  }

  if (url.protocol !== 'https:' && !(config.allowInsecure && url.protocol === 'http:')) {

    throw new GatewayError(502, 'upstream_url_protocol_rejected');

  }

  if (!allowedHosts.has(url.host.toLowerCase())) {

    throw new GatewayError(502, 'upstream_host_rejected', url.host);

  }

  return url;

}


async function fetchWithValidatedRedirects(config, fetchImpl, initialUrl, options, allowedHosts) {

  let target = assertSafeUpstreamUrl(config, initialUrl, allowedHosts);

  for (let redirectCount = 0; redirectCount <= 4; redirectCount += 1) {

    let response;

    try {

      response = await fetchImpl(target, { ...options, redirect: 'manual' });

    } catch (error) {

      throw new GatewayError(502, 'upstream_network_error', error.message);

    }

    if (![301, 302, 303, 307, 308].includes(response.status)) return response;

    const location = response.headers.get('location');

    if (!location) throw new GatewayError(502, 'upstream_redirect_missing_location');

    if (redirectCount === 4) throw new GatewayError(502, 'too_many_upstream_redirects');

    target = assertSafeUpstreamUrl(config, new URL(location, target), allowedHosts);

  }

  throw new GatewayError(502, 'too_many_upstream_redirects');

}


async function fetchUpstreamPackument(config, fetchImpl, request, packageName) {

  const url = new URL(encodeURIComponent(packageName), config.upstreamRegistry);

  const response = await fetchWithValidatedRedirects(

    config,

    fetchImpl,

    url,

    { method: 'GET', headers: upstreamHeaders(config, request) },

    new Set([config.upstreamRegistry.host.toLowerCase()]),

  );

  if (response.status === 404) return null;

  if (!response.ok) {

    throw new GatewayError(502, 'upstream_metadata_error', `status ${response.status}`);

  }

  try {

    const document = await response.json();

    if (!document || typeof document !== 'object') throw new Error('not an object');

    return document;

  } catch (error) {

    throw new GatewayError(502, 'invalid_upstream_metadata', error.message);

  }

}


function publicOrigin(config, request) {

  if (config.publicBaseUrl) return config.publicBaseUrl.toString().replace(/\/$/, '');

  if (config.isVercel) throw new GatewayError(500, 'public_base_url_not_configured');

  const protocol = String(request.headers['x-forwarded-proto'] ?? 'http').split(',')[0].trim();

  const host = String(request.headers['x-forwarded-host'] ?? request.headers.host ?? '').split(',')[0].trim();

  if (!['http', 'https'].includes(protocol) || !/^[a-z0-9.-]+(?::[0-9]{1,5})?$/i.test(host)) {

    throw new GatewayError(500, 'public_base_url_not_configured');

  }

  return `${protocol}://${host}`;

}


function tarballUrl(origin, packageName, version) {

  const packageToken = Buffer.from(packageName, 'utf8').toString('base64url');

  return `${origin}/-/tarballs/${packageToken}/${encodeURIComponent(version)}.tgz`;

}


function cacheHeaders(config, resource) {

  if (config.authMode !== 'none' && !config.allowAnonymous) {

    return {

      cacheControl: 'private, no-store',

      cdnCacheControl: 'private, no-store',

    };

  }

  if (resource === 'tarball') {

    return {

      cacheControl: 'public, max-age=31536000, immutable',

      cdnCacheControl: 'public, s-maxage=31536000, immutable',

    };

  }

  return {

    cacheControl: 'public, max-age=0, must-revalidate',

    cdnCacheControl: 'public, s-maxage=300, stale-while-revalidate=86400',

  };

}


function chooseLatest(config, packageName, versions, upstreamTags, customTags) {

  if (customTags?.latest && versions[customTags.latest]) return customTags.latest;

  if (upstreamTags?.latest && versions[upstreamTags.latest]) return upstreamTags.latest;

  const configured = config.policy?.allow?.[packageName];

  if (Array.isArray(configured)) {

    const allowed = configured.filter((version) => versions[version]);

    if (allowed.length > 0) return allowed.at(-1);

  }

  return Object.keys(versions).at(-1) ?? null;

}


function buildPackument(config, request, packageName, upstream, customPackage) {

  const origin = publicOrigin(config, request);

  const upstreamVersions = permittedUpstreamVersions(config, packageName, upstream?.versions);

  const versions = {};


  for (const [version, manifest] of Object.entries(upstreamVersions)) {

    versions[version] = {

      ...manifest,

      dist: {
        ...(manifest.dist ?? {}),
        tarball: manifest.dist?.tarball
          ? manifest.dist.tarball
          : tarballUrl(origin, packageName, version),
      },

    };

  }


  for (const [version, customVersion] of Object.entries(customPackage?.versions ?? {})) {

    const decision = policyDecision(config, packageName, version);

    if (!decision.allowed) continue;

    versions[version] = {

      ...customVersion.manifest,

      name: packageName,

      version,

      _id: `${packageName}@${version}`,

      dist: {

        tarball: tarballUrl(origin, packageName, version),

        integrity: customVersion.integrity,

        shasum: customVersion.shasum,

      },

    };

  }


  const upstreamTags = Object.fromEntries(

    Object.entries(upstream?.['dist-tags'] ?? {}).filter(([, version]) => versions[version]),

  );

  const customTags = Object.fromEntries(

    Object.entries(customPackage?.distTags ?? {}).filter(([, version]) => versions[version]),

  );

  const distTags = { ...upstreamTags, ...customTags };

  const latest = chooseLatest(config, packageName, versions, upstreamTags, customTags);

  if (latest) distTags.latest = latest;


  const time = Object.fromEntries(

    Object.entries(upstream?.time ?? {}).filter(([key]) => key === 'created' || key === 'modified' || versions[key]),

  );

  for (const [version, customVersion] of Object.entries(customPackage?.versions ?? {})) {

    if (versions[version]) time[version] = customVersion.registeredAt ?? new Date(0).toISOString();

  }


  const packument = {

    ...(upstream ?? {}),

    _id: packageName,

    name: packageName,

    'dist-tags': distTags,

    versions,

    time,

  };

  delete packument._attachments;

  return packument;

}


async function serveMetadata(config, fetchImpl, audit, request, response, principal, context, packageName) {

  if (!validPackageName(packageName)) throw new GatewayError(400, 'invalid_package_name');

  const packageDecision = policyDecision(config, packageName);

  if (!packageDecision.allowed) throw new GatewayError(403, packageDecision.reason);

  
  const registeredPackage = getCustomPackage(config, packageName);
  
  const customPackage = registeredPackage
      ? { ...registeredPackage, replaceUpstream: true }
      : { ...registeredPackage, replaceUpstream: false };

  const upstream = customPackage?.replaceUpstream
      ? null
      : await fetchUpstreamPackument(config, fetchImpl, request, packageName);

  if (!upstream && !customPackage) throw new GatewayError(404, 'package_not_found');

  const packument = buildPackument(config, request, packageName, upstream, customPackage);

  if (Object.keys(packument.versions).length === 0) {

    throw new GatewayError(403, 'no_permitted_versions');

  }


  const body = Buffer.from(JSON.stringify(packument));

  const etag = `W/\"${createHash('sha256').update(body).digest('base64url')}\"`;

  response.statusCode = 200;

  response.setHeader('content-type', 'application/json; charset=utf-8');

  response.setHeader('content-length', String(body.length));

  const metadataCache = cacheHeaders(config, 'metadata');

  response.setHeader('cache-control', metadataCache.cacheControl);

  response.setHeader('cdn-cache-control', metadataCache.cdnCacheControl);

  response.setHeader('etag', etag);

  response.end(request.method === 'HEAD' ? undefined : body);


  await audit({

    ...context,

    principal,

    action: 'package_metadata',

    package: packageName,

    source: upstream && customPackage ? 'mixed' : customPackage ? 'custom' : 'upstream',

    permittedVersionCount: Object.keys(packument.versions).length,

    result: 'success',

  });

}


function parseTarballRoute(pathValue) {

  const match = /^-\/tarballs\/([a-z0-9_-]+)\/([^/]+)\.tgz$/i.exec(pathValue);

  if (match) {

    let packageName;

    try {

      packageName = Buffer.from(match[1], 'base64url').toString('utf8');

    } catch {

      throw new GatewayError(400, 'invalid_tarball_package_token');

    }

    const version = safeDecode(match[2]);

    if (!validPackageName(packageName) || !validVersion(version)) {

      throw new GatewayError(400, 'invalid_tarball_identity');

    }

    return { packageName, version };

  }


  // npm lockfiles can contain the conventional registry URL

  // \<package>/-/\<package>-\<version>.tgz. Support it as well as the gateway's

  // compact internal URL so existing lockfiles remain installable.

  const segments = pathValue.split('/');

  if (segments.length >= 3 && segments.at(-2) === '-') {

    const packageName = segments.slice(0, -2).join('/');

    const filename = segments.at(-1);

    if (!filename.endsWith('.tgz') || !validPackageName(packageName)) return null;

    const basename = filename.slice(0, -'.tgz'.length);

    const packageLeaf = packageName.split('/').at(-1);

    const prefix = `${packageLeaf}-`;

    if (!basename.startsWith(prefix)) return null;

    const version = safeDecode(basename.slice(prefix.length));

    if (!validVersion(version)) throw new GatewayError(400, 'invalid_tarball_identity');

    return { packageName, version };

  }

  return null;

}


async function serveCustomTarball(config, audit, request, response, principal, context, identity, customVersion) {

  const filePath = resolveCustomTarball(config, customVersion.file);

  let stats;

  try {

    stats = statSync(filePath);

  } catch {

    throw new GatewayError(500, 'custom_tarball_missing');

  }

  if (!stats.isFile()) throw new GatewayError(500, 'custom_tarball_not_a_file');


  response.statusCode = 200;

  response.setHeader('content-type', 'application/octet-stream');

  response.setHeader('content-length', String(stats.size));

  const tarballCache = cacheHeaders(config, 'tarball');

  response.setHeader('cache-control', tarballCache.cacheControl);

  response.setHeader('cdn-cache-control', tarballCache.cdnCacheControl);

  response.setHeader('x-content-type-options', 'nosniff');

  response.setHeader('etag', `\"${customVersion.shasum}\"`);

  if (request.method === 'HEAD') {

    response.end();

  } else {

    await pipeline(createReadStream(filePath), response);

  }


  await audit({

    ...context,

    principal,

    action: 'tarball_download',

    package: identity.packageName,

    version: identity.version,

    source: 'custom',

    bytes: request.method === 'HEAD' ? 0 : stats.size,

    integrityVerified: true,

    result: 'success',

  });

}


async function serveUpstreamTarball(config, fetchImpl, audit, request, response, principal, context, identity) {

  const packument = await fetchUpstreamPackument(config, fetchImpl, request, identity.packageName);

  const manifest = packument?.versions?.[identity.version];

  if (!manifest?.dist?.tarball) throw new GatewayError(404, 'package_version_not_found');


  const headers = upstreamHeaders(config, request);

  headers.accept = 'application/octet-stream';

  if (request.headers.range) headers.range = request.headers.range;

  const upstream = await fetchWithValidatedRedirects(

    config,

    fetchImpl,

    manifest.dist.tarball,

    { method: request.method, headers },

    config.allowedTarballHosts,

  );

  if (!upstream.ok && upstream.status !== 206) {

    throw new GatewayError(502, 'upstream_tarball_error', `status ${upstream.status}`);

  }


  response.statusCode = upstream.status;

  const tarballCache = cacheHeaders(config, 'tarball');

  copyResponseHeaders(upstream, response, tarballCache.cacheControl);

  response.setHeader('cdn-cache-control', tarballCache.cdnCacheControl);

  let transfer = { bytes: 0, integrityVerified: null };

  if (request.method === 'HEAD') {

    response.end();

  } else {

    transfer = await streamFetchBody(

      upstream,

      response,

      request.headers.range ? '' : manifest.dist.integrity,

    );

  }


  await audit({

    ...context,

    principal,

    action: 'tarball_download',

    package: identity.packageName,

    version: identity.version,

    source: 'upstream',

    bytes: transfer.bytes,

    integrityVerified: transfer.integrityVerified,

    result: transfer.integrityVerified === false ? 'integrity_mismatch' : 'success',

  });

}


async function serveTarball(config, fetchImpl, audit, request, response, principal, context, identity) {

  const decision = policyDecision(config, identity.packageName, identity.version);

  if (!decision.allowed) throw new GatewayError(403, decision.reason);

  const customVersion = getCustomVersion(config, identity.packageName, identity.version);

  if (customVersion) {

    await serveCustomTarball(config, audit, request, response, principal, context, identity, customVersion);

    return;

  }

  await serveUpstreamTarball(config, fetchImpl, audit, request, response, principal, context, identity);

}


async function proxyAuditRequest(config, fetchImpl, audit, request, response, principal, context, pathValue) {

  const contentType = request.headers['content-type'] ?? 'application/json';

  const requestBody = await readBody(request, 2_000_000);

  const target = new URL(pathValue, config.upstreamRegistry);

  const headers = upstreamHeaders(config, request, contentType);

  headers.accept = request.headers.accept ?? 'application/json';

  // npm sends bulk audit JSON compressed with gzip. Keep the encoding header
  // when forwarding the original request bytes to the upstream registry.
  if (request.headers['content-encoding']) {
    headers['content-encoding'] = request.headers['content-encoding'];
  }

  const upstream = await fetchWithValidatedRedirects(

    config,

    fetchImpl,

    target,

    {

      method: 'POST',

      headers,

      body: requestBody,

    },

    new Set([config.upstreamRegistry.host.toLowerCase()]),

  );

  response.statusCode = upstream.status;

  copyResponseHeaders(upstream, response);

  const transfer = await streamFetchBody(upstream, response);

  await audit({

    ...context,

    principal,

    action: 'npm_security_audit',

    endpoint: pathValue,

    requestBytes: requestBody.length,

    responseBytes: transfer.bytes,

    result: upstream.ok ? 'success' : 'upstream_error',

  });

}


async function acceptDependencyReport(audit, request, response, principal, context) {

  const raw = await readBody(request, 1_000_000);

  let report;

  try {

    report = JSON.parse(raw.toString('utf8'));

  } catch {

    throw new GatewayError(400, 'invalid_dependency_report_json');

  }

  if (!report || !Array.isArray(report.dependencies) || report.dependencies.length > 10_000) {

    throw new GatewayError(400, 'invalid_dependency_report');

  }

  if (typeof report.lockfileHash !== 'string' || !/^[a-f0-9]{64}$/i.test(report.lockfileHash)) {

    throw new GatewayError(400, 'invalid_lockfile_hash');

  }

  const dependencies = report.dependencies.map((entry) => {

    if (!validPackageName(entry?.name) || !validVersion(entry?.version)) {

      throw new GatewayError(400, 'invalid_dependency_report_entry');

    }

    return { name: entry.name, version: entry.version };

  });

  const reportHash = createHash('sha256').update(raw).digest('hex');


  const chunks = dependencies.length === 0 ? [[]] : Array.from(

    { length: Math.ceil(dependencies.length / 100) },

    (_, index) => dependencies.slice(index * 100, index * 100 + 100),

  );

  for (let index = 0; index < chunks.length; index += 1) {

    await audit({

      ...context,

      principal,

      action: 'dependency_report',

      project: typeof report.project === 'string' ? report.project.slice(0, 200) : undefined,

      lockfileHash: report.lockfileHash,

      reportHash,

      chunk: index + 1,

      dependencies: chunks[index],

      result: 'success',

    });

  }

  writeJson(response, 202, { accepted: true, dependencies: dependencies.length, reportHash }, request.method);

}


export function createGateway(options = {}) {

  const config = options.config ?? loadConfig(options.env ?? process.env);

  const fetchImpl = options.fetchImpl ?? globalThis.fetch;

  const auditEmitter = options.auditEmitter ?? emitAudit;

  const audit = (event) => auditEmitter(config, fetchImpl, event);


  return async function gateway(request, response) {

    const context = requestContext(request, config);

    response.setHeader('x-content-type-options', 'nosniff');

    response.setHeader('referrer-policy', 'no-referrer');


    const authentication = authenticate(request, config);

    if (!authentication.ok) {

      await audit({

        ...context,

        principal: null,

        action: 'authentication',

        result: authentication.code,

      });

      writeJson(

        response,

        authentication.status,

        { error: authentication.code },

        request.method,

        authentication.status === 401 ? { 'www-authenticate': 'Bearer realm="company-npm-gateway"' } : {},

      );

      return;

    }


    const principal = authentication.principal;

    try {

      const pathValue = registryPath(request);

      const method = request.method ?? 'GET';


      if (method === 'GET' && pathValue === '') {

        writeJson(response, 200, {

          service: 'company-npm-gateway',

          policyMode: config.policyMode,

          upstream: config.upstreamRegistry.host,

        }, method);

        return;

      }

      if ((method === 'GET' || method === 'HEAD') && pathValue === '-/ping') {

        writeJson(response, 200, { ok: true }, method);

        return;

      }

      if (method === 'GET' && pathValue === '-/whoami') {

        writeJson(response, 200, { username: principal }, method);

        return;

      }

      if (method === 'POST' && pathValue === '-/company/report') {

        await acceptDependencyReport(audit, request, response, principal, context);

        return;

      }

      if (method === 'POST' && AUDIT_ENDPOINTS.has(pathValue)) {

        await proxyAuditRequest(config, fetchImpl, audit, request, response, principal, context, pathValue);

        return;

      }


      const tarballIdentity = parseTarballRoute(pathValue);

      if (tarballIdentity && (method === 'GET' || method === 'HEAD')) {

        await serveTarball(config, fetchImpl, audit, request, response, principal, context, tarballIdentity);

        return;

      }

      if (method === 'GET' || method === 'HEAD') {

        await serveMetadata(config, fetchImpl, audit, request, response, principal, context, pathValue);

        return;

      }


      throw new GatewayError(405, 'method_not_allowed');

    } catch (error) {

      const status = error.status ?? 500;

      const code = error.code ?? 'internal_error';

      await audit({

        ...context,

        principal,

        action: 'request_error',

        result: code,

        status,

      });

      if (!response.headersSent) {

        writeJson(response, status, { error: code }, request.method);

      } else {

        response.destroy(error);

      }

    }

  };

}
