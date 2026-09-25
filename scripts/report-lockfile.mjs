import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function packageNameFromLockPath(lockPath, entry) {
  if (entry?.name) return entry.name;
  const marker = 'node_modules/';
  const index = lockPath.lastIndexOf(marker);
  return index === -1 ? '' : lockPath.slice(index + marker.length);
}

export function dependenciesFromLockfile(lockfile) {
  const dependencies = new Map();
  for (const [lockPath, entry] of Object.entries(lockfile.packages ?? {})) {
    if (!lockPath || !entry?.version) continue;
    const name = packageNameFromLockPath(lockPath, entry);
    if (!name) continue;
    dependencies.set(`${name}@${entry.version}`, { name, version: entry.version });
  }

  if (dependencies.size === 0) {
    for (const [name, entry] of Object.entries(lockfile.dependencies ?? {})) {
      if (entry?.version) dependencies.set(`${name}@${entry.version}`, { name, version: entry.version });
    }
  }
  return [...dependencies.values()].sort((left, right) => (
    left.name.localeCompare(right.name) || left.version.localeCompare(right.version)
  ));
}

export async function reportLockfile(options = {}) {
  const directory = path.resolve(options.directory ?? process.cwd());
  const lockfilePath = path.join(directory, 'package-lock.json');
  const raw = await readFile(lockfilePath);
  const lockfile = JSON.parse(raw.toString('utf8'));
  const gatewayValue = options.gatewayUrl ?? process.env.NPM_GATEWAY_URL;
  const token = options.token ?? process.env.NPM_GATEWAY_TOKEN;
  if (!gatewayValue) throw new Error('NPM_GATEWAY_URL is required, for example https://gateway.vercel.app/npm/');
  if (!token) throw new Error('NPM_GATEWAY_TOKEN is required');
  const gatewayUrl = new URL(gatewayValue.endsWith('/') ? gatewayValue : `${gatewayValue}/`);
  const endpoint = new URL('-/company/report', gatewayUrl);
  const dependencies = dependenciesFromLockfile(lockfile);
  const report = {
    project: lockfile.name ?? path.basename(directory),
    lockfileVersion: lockfile.lockfileVersion,
    lockfileHash: createHash('sha256').update(raw).digest('hex'),
    dependencies,
  };

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      'user-agent': 'company-npm-reporter/1.0',
    },
    body: JSON.stringify(report),
    redirect: 'error',
  });
  if (!response.ok) {
    throw new Error(`Dependency report failed with HTTP ${response.status}: ${await response.text()}`);
  }
  const result = await response.json();
  // console.log(`Reported ${result.dependencies} locked dependencies (${result.reportHash})`);
  return result;
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  reportLockfile().catch((error) => {
    // console.error(error.message);
    process.exit(1);
  });
}
