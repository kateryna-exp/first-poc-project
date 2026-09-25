import { createHash, randomBytes } from 'node:crypto';

const principal = process.argv[2] ?? 'developer';
if (!/^[a-z0-9][a-z0-9._-]{0,99}$/i.test(principal)) {
  console.error('Principal must use 1-100 letters, digits, dots, underscores, or hyphens.');
  process.exit(1);
}

const token = randomBytes(32).toString('base64url');
const digest = createHash('sha256').update(token, 'utf8').digest('hex');

// console.log(`Principal: ${principal}`);
// console.log(`Developer token (show once): ${token}`);
// console.log(`Hash for GATEWAY_TOKEN_HASHES_JSON: ${digest}`);
// console.log(`JSON entry: ${JSON.stringify({ [principal]: digest })}`);
