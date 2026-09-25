import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createHash } from 'node:crypto';

export function writeJson(response, status, body, method = 'GET', extraHeaders = {}) {
  const bytes = Buffer.from(JSON.stringify(body));
  response.statusCode = status;
  response.setHeader('content-type', 'application/json; charset=utf-8');
  response.setHeader('content-length', String(bytes.length));
  response.setHeader('cache-control', 'private, no-store');
  for (const [name, value] of Object.entries(extraHeaders)) {
    response.setHeader(name, value);
  }
  response.end(method === 'HEAD' ? undefined : bytes);
}

export async function readBody(request, maximumBytes = 1_000_000) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maximumBytes) {
      const error = new Error('request_body_too_large');
      error.status = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

export function copyResponseHeaders(upstream, response, cacheControl = 'private, no-store') {
  for (const name of [
    'content-type',
    'content-length',
    'content-range',
    'accept-ranges',
    'etag',
    'last-modified',
  ]) {
    const value = upstream.headers.get(name);
    if (value) response.setHeader(name, value);
  }
  response.setHeader('cache-control', cacheControl);
  response.setHeader('x-content-type-options', 'nosniff');
}

function integrityAlgorithm(integrity) {
  if (typeof integrity !== 'string') return null;
  const candidates = integrity.split(/\s+/);
  for (const algorithm of ['sha512', 'sha384', 'sha256', 'sha1']) {
    const match = candidates.find((candidate) => candidate.startsWith(`${algorithm}-`));
    if (match) return { algorithm, expected: match.slice(algorithm.length + 1) };
  }
  return null;
}

export async function streamFetchBody(upstream, response, expectedIntegrity = '') {
  if (!upstream.body) {
    response.end();
    return { bytes: 0, integrityVerified: null };
  }

  const selectedIntegrity = integrityAlgorithm(expectedIntegrity);
  const hash = selectedIntegrity ? createHash(selectedIntegrity.algorithm) : null;
  let bytes = 0;
  const meter = new Transform({
    transform(chunk, encoding, callback) {
      bytes += chunk.length;
      hash?.update(chunk);
      callback(null, chunk);
    },
  });

  await pipeline(Readable.fromWeb(upstream.body), meter, response);
  const integrityVerified = selectedIntegrity
    ? hash.digest('base64') === selectedIntegrity.expected
    : null;
  return { bytes, integrityVerified };
}
