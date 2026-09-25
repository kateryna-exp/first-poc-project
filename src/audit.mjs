import { createHash, createHmac, randomUUID } from 'node:crypto';

function truncate(value, maximum) {
  if (typeof value !== 'string') return undefined;
  return value.slice(0, maximum);
}

function ipAddress(request) {
  const forwarded = request.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') return forwarded.split(',')[0].trim();
  return request.socket?.remoteAddress ?? '';
}

export function requestContext(request, config) {
  const rawIp = ipAddress(request);
  const context = {
    requestId: truncate(request.headers['x-vercel-id'], 200) ?? randomUUID(),
  };

  if (config.auditIncludeUserAgent) {
    context.userAgent = truncate(request.headers['user-agent'], 300);
  }
  if (config.auditIpSalt && rawIp) {
    context.ipHash = createHash('sha256')
      .update(`${config.auditIpSalt}:${rawIp}`, 'utf8')
      .digest('hex');
  }
  return context;
}

async function postWebhook(config, body, fetchImpl) {
  if (!config.auditWebhookUrl) return;

  const serialized = JSON.stringify(body);
  const headers = { 'content-type': 'application/json' };
  if (config.auditWebhookSecret) {
    headers['x-company-signature'] = `sha256=${createHmac('sha256', config.auditWebhookSecret)
      .update(serialized)
      .digest('hex')}`;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 2_000);
  try {
    const response = await fetchImpl(config.auditWebhookUrl, {
      method: 'POST',
      headers,
      body: serialized,
      signal: controller.signal,
      redirect: 'error',
    });
    if (!response.ok) {
      console.error(JSON.stringify({
        type: 'npm_gateway_audit_delivery_error',
        status: response.status,
      }));
    }
  } catch (error) {
    console.error(JSON.stringify({
      type: 'npm_gateway_audit_delivery_error',
      error: error.name === 'AbortError' ? 'timeout' : truncate(error.message, 300),
    }));
  } finally {
    clearTimeout(timeout);
  }
}

export async function emitAudit(config, fetchImpl, event) {
  const record = {
    type: 'npm_gateway_audit',
    schemaVersion: 1,
    timestamp: new Date().toISOString(),
    ...event,
  };
  console.log(JSON.stringify(record));
  await postWebhook(config, record, fetchImpl);
}
