import { createHash } from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { gunzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDirectory, '..');

function parseArguments(argv) {
  const options = {
    tarball: '',
    tag: 'company',
    setLatest: false,
    replace: false,
    replaceUpstream: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--set-latest') options.setLatest = true;
    else if (argument === '--replace') options.replace = true;
    else if (argument === '--replace-upstream') options.replaceUpstream = true;
    else if (argument === '--tag') options.tag = argv[++index] ?? '';
    else if (argument.startsWith('--tag=')) options.tag = argument.slice('--tag='.length);
    else if (!argument.startsWith('-') && !options.tarball) options.tarball = argument;
    else throw new Error(`Unknown argument: ${argument}`);
  }
  if (!options.tarball) {
    throw new Error('Usage: npm run register-package -- <package.tgz> [--tag company] [--set-latest] [--replace-upstream]');
  }
  if (options.tag && !/^[a-z0-9][a-z0-9._-]{0,63}$/i.test(options.tag)) {
    throw new Error('Tag contains unsupported characters');
  }
  return options;
}

function nullTerminated(buffer) {
  const end = buffer.indexOf(0);
  return buffer.subarray(0, end === -1 ? buffer.length : end).toString('utf8');
}

function extractPackageJson(tarball) {
  if (tarball.length > 100 * 1024 * 1024) {
    throw new Error('Custom tarball exceeds the 100 MiB registration limit');
  }
  const archive = gunzipSync(tarball, { maxOutputLength: 256 * 1024 * 1024 });
  let offset = 0;
  while (offset + 512 <= archive.length) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const name = nullTerminated(header.subarray(0, 100));
    const prefix = nullTerminated(header.subarray(345, 500));
    const fullName = prefix ? `${prefix}/${name}` : name;
    const sizeText = nullTerminated(header.subarray(124, 136)).trim().replace(/\0/g, '');
    const size = Number.parseInt(sizeText || '0', 8);
    if (!Number.isFinite(size) || size < 0) throw new Error('Invalid tar entry size');
    const contentStart = offset + 512;
    if (fullName === 'package/package.json' || fullName === './package/package.json') {
      const raw = archive.subarray(contentStart, contentStart + size).toString('utf8');
      return JSON.parse(raw);
    }
    offset = contentStart + Math.ceil(size / 512) * 512;
  }
  throw new Error('The tarball does not contain package/package.json');
}

function validPackageName(name) {
  return typeof name === 'string'
    && name.length <= 214
    && (/^@[a-z0-9._~-]+\/[a-z0-9._~-]+$/i.test(name) || /^[a-z0-9_~][a-z0-9._~-]*$/i.test(name));
}

function validVersion(version) {
  return typeof version === 'string'
    && version.length <= 128
    && /^[0-9a-z][0-9a-z.+_-]*$/i.test(version);
}

function sanitizedManifest(manifest) {
  const copy = { ...manifest };
  for (const key of ['dist', '_id', '_integrity', '_resolved', '_from']) delete copy[key];
  return copy;
}

try {
  const options = parseArguments(process.argv.slice(2));
  const source = path.resolve(options.tarball);
  if (!existsSync(source)) throw new Error(`Tarball not found: ${source}`);
  const tarball = readFileSync(source);
  const manifest = extractPackageJson(tarball);
  if (!validPackageName(manifest.name)) throw new Error(`Invalid package name: ${manifest.name}`);
  if (!validVersion(manifest.version)) throw new Error(`Invalid package version: ${manifest.version}`);

  const safeName = manifest.name
    .replace(/^@/, '')
    .replace('/', '--')
    .replace(/[^a-z0-9._+-]/gi, '-');
  const safeVersion = manifest.version.replace(/[^a-z0-9._+-]/gi, '-');
  const destinationDirectory = path.join(root, 'packages');
  const destination = path.join(destinationDirectory, `${safeName}-${safeVersion}.tgz`);
  const relativeDestination = path.relative(root, destination).split(path.sep).join('/');
  const configPath = path.join(root, 'config/custom-packages.json');
  const config = JSON.parse(readFileSync(configPath, 'utf8'));
  config.packages ??= {};

  const currentPackage = config.packages[manifest.name] ?? {
    replaceUpstream: false,
    distTags: {},
    versions: {},
  };
  if (currentPackage.versions?.[manifest.version] && !options.replace) {
    throw new Error(`${manifest.name}@${manifest.version} is already registered; bump the version or pass --replace explicitly`);
  }
  if (existsSync(destination) && path.resolve(destination) !== source && !options.replace) {
    throw new Error(`Destination already exists: ${destination}`);
  }

  mkdirSync(destinationDirectory, { recursive: true });
  if (path.resolve(destination) !== source) copyFileSync(source, destination);
  const integrity = `sha512-${createHash('sha512').update(tarball).digest('base64')}`;
  const shasum = createHash('sha1').update(tarball).digest('hex');

  currentPackage.replaceUpstream = options.replaceUpstream || currentPackage.replaceUpstream;
  currentPackage.distTags ??= {};
  currentPackage.versions ??= {};
  if (options.tag) currentPackage.distTags[options.tag] = manifest.version;
  if (options.setLatest) currentPackage.distTags.latest = manifest.version;
  currentPackage.versions[manifest.version] = {
    file: relativeDestination,
    integrity,
    shasum,
    registeredAt: new Date().toISOString(),
    manifest: sanitizedManifest(manifest),
  };
  config.packages[manifest.name] = currentPackage;
  writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, 'utf8');

  // console.log(`Registered ${manifest.name}@${manifest.version}`);
  // console.log(`Tarball: ${relativeDestination}`);
  // console.log(`Integrity: ${integrity}`);
  if (!manifest.version.includes('-company.')) {
    console.warn('Recommendation: use a distinct version such as 1.2.3-company.1 and pin it with package.json overrides.');
  }
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
