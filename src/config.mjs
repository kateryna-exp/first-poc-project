import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const sourceDirectory = path.dirname(fileURLToPath(import.meta.url));
export const projectRoot = path.resolve(sourceDirectory, '..');

function readJson(filePath, label) {
  try {
    return JSON.parse(readFileSync(filePath, 'utf8'));
  } catch (error) {
    throw new Error(`Unable to read ${label} at ${filePath}: ${error.message}`);
  }
}

function parseJsonEnvironment(value, label, fallback) {
  if (!value) return fallback;
  try {
    const parsed = JSON.parse(value);
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
      throw new Error('expected a JSON object');
    }
    return parsed;
  } catch (error) {
    throw new Error(`${label} must be valid JSON: ${error.message}`);
  }
}

function parseBoolean(value, fallback = false) {
  if (value === undefined || value === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function normalizeBaseUrl(value, label, allowInsecure) {
  const url = new URL(value);
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(`${label} cannot contain credentials, a query, or a fragment`);
  }
  if (url.protocol !== 'https:' && !allowInsecure) {
    throw new Error(`${label} must use HTTPS`);
  }
  url.pathname = `${url.pathname.replace(/\/+$/, '')}/`;
  return url;
}

function validateTokenHashes(tokenHashes) {
  for (const [principal, digest] of Object.entries(tokenHashes)) {
    if (!principal || principal.length > 100) {
      throw new Error('Gateway token principal IDs must contain 1 to 100 characters');
    }
    if (typeof digest !== 'string' || !/^[a-f0-9]{64}$/i.test(digest)) {
      throw new Error(`Gateway token hash for ${principal} must be a 64-character SHA-256 hex digest`);
    }
  }
}

export function loadConfig(env = process.env) {
  const allowInsecure = parseBoolean(env.ALLOW_INSECURE_UPSTREAM, false);
  const policyPath = path.resolve(env.PACKAGE_POLICY_FILE ?? path.join(projectRoot, 'config/package-policy.json'));
  const customPath = path.resolve(env.CUSTOM_PACKAGES_FILE ?? path.join(projectRoot, 'config/custom-packages.json'));
  const policy = readJson(policyPath, 'package policy');
  const custom = readJson(customPath, 'custom package index');
  const policyMode = env.PACKAGE_POLICY_MODE ?? policy.mode ?? 'allowlist';

  if (!['log-only', 'allowlist'].includes(policyMode)) {
    throw new Error('PACKAGE_POLICY_MODE must be log-only or allowlist');
  }

  const upstreamRegistry = normalizeBaseUrl(
    env.UPSTREAM_REGISTRY_URL ?? 'https://registry.npmjs.org/',
    'UPSTREAM_REGISTRY_URL',
    allowInsecure,
  );

  const publicBaseUrl = env.PUBLIC_BASE_URL
    ? normalizeBaseUrl(env.PUBLIC_BASE_URL, 'PUBLIC_BASE_URL', allowInsecure)
    : null;

  const auditWebhookUrl = env.AUDIT_WEBHOOK_URL
    ? normalizeBaseUrl(env.AUDIT_WEBHOOK_URL, 'AUDIT_WEBHOOK_URL', allowInsecure)
    : null;

  const authMode = env.AUTH_MODE ?? (parseBoolean(env.ALLOW_ANONYMOUS, false) ? 'none' : 'token');
  if (!['token', 'none'].includes(authMode)) {
    throw new Error('AUTH_MODE must be token or none');
  }
  const tokenHashes = authMode === 'token'
    ? parseJsonEnvironment(env.GATEWAY_TOKEN_HASHES_JSON, 'GATEWAY_TOKEN_HASHES_JSON', {})
    : {};
  if (authMode === 'token') validateTokenHashes(tokenHashes);

  const configuredHosts = (env.UPSTREAM_TARBALL_HOSTS ?? upstreamRegistry.host)
    .split(',')
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);

  return {
    projectRoot,
    policy,
    custom,
    policyMode,
    upstreamRegistry,
    upstreamToken: env.UPSTREAM_NPM_TOKEN ?? '',
    allowedTarballHosts: new Set(configuredHosts),
    publicBaseUrl,
    isVercel: Boolean(env.VERCEL),
    allowInsecure,
    tokenHashes,
    authMode,
    allowAnonymous: authMode === 'none',
    auditWebhookUrl,
    auditWebhookSecret: env.AUDIT_WEBHOOK_SECRET ?? '',
    auditIpSalt: env.AUDIT_IP_SALT ?? '',
    auditIncludeUserAgent: parseBoolean(env.AUDIT_INCLUDE_USER_AGENT, true),
  };
}

function versionsFor(map, packageName) {
  const value = map?.[packageName];
  return Array.isArray(value) ? value : [];
}

export function getCustomPackage(config, packageName) {
  return config.custom?.packages?.[packageName] ?? null;
}

export function getCustomVersion(config, packageName, version) {
  return getCustomPackage(config, packageName)?.versions?.[version] ?? null;
}

export function policyDecision(config, packageName, version = null) {
  const denied = versionsFor(config.policy?.deny, packageName);
  if (denied.includes('*') || (version !== null && denied.includes(version))) {
    return { allowed: false, reason: 'denylist' };
  }

  const customPackage = getCustomPackage(config, packageName);
  if (
    customPackage
    && (version === null || Object.hasOwn(customPackage.versions ?? {}, version))
  ) {
    return { allowed: true, reason: 'custom' };
  }

  if (config.policyMode === 'log-only') {
    return { allowed: true, reason: 'log-only' };
  }

  const allowed = versionsFor(config.policy?.allow, packageName);
  if (version === null && allowed.length > 0) {
    return { allowed: true, reason: 'allowlist' };
  }
  if (version !== null && (allowed.includes('*') || allowed.includes(version))) {
    return { allowed: true, reason: 'allowlist' };
  }

  return { allowed: false, reason: 'not_allowlisted' };
}

export function permittedUpstreamVersions(config, packageName, versions) {
  return Object.fromEntries(
    Object.entries(versions ?? {}).filter(([version]) => {
      const decision = policyDecision(config, packageName, version);
      return decision.allowed && decision.reason !== 'custom';
    }),
  );
}

export function resolveCustomTarball(config, relativePath) {
  if (typeof relativePath !== 'string' || !relativePath.startsWith('packages/')) {
    throw new Error('Custom tarball path must be inside packages/');
  }
  const packageDirectory = path.resolve(config.projectRoot, 'packages');
  const absolutePath = path.resolve(config.projectRoot, relativePath);
  if (absolutePath !== packageDirectory && !absolutePath.startsWith(`${packageDirectory}${path.sep}`)) {
    throw new Error('Custom tarball path escapes packages/');
  }
  return absolutePath;
}
