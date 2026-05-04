const crypto = require('crypto');
const { parseJsonBody, sendJson } = require('../../../src/lib/http');
const { audit, auditError } = require('../../../src/lib/audit');
const { validateWithGuardian } = require('../../../src/lib/openclawGuardian');

module.exports = async function handler(req, res) {
  const start = Date.now();
  const correlationId = req.headers['x-correlation-id'] || crypto.randomUUID();
  res.setHeader('x-correlation-id', correlationId);

  // CORS mínimo (ajuste para allowlist em produção)
  res.setHeader('access-control-allow-origin', '*');
  res.setHeader('access-control-allow-headers', 'content-type, x-correlation-id, authorization');
  res.setHeader('access-control-allow-methods', 'POST, OPTIONS');

  if (req.method === 'OPTIONS') return res.end();

  if (req.method !== 'POST') {
    return sendJson(res, 405, { error: 'method_not_allowed', correlationId });
  }

  let body;
  try {
    body = await parseJsonBody(req);
  } catch (err) {
    return sendJson(res, err.statusCode || 400, { error: err.message, correlationId });
  }

  // Contrato mínimo de entrada
  const content = body?.content;
  const metadata = body?.metadata;

  if (typeof content !== 'string' || !content.trim()) {
    return sendJson(res, 400, { error: 'invalid_input', details: 'content is required', correlationId });
  }
  if (!metadata || typeof metadata !== 'object') {
    return sendJson(res, 400, { error: 'invalid_input', details: 'metadata is required', correlationId });
  }

  const timeoutMs = Number(process.env.GUARDIAN_TIMEOUT_MS || 3500);

  const input = {
    content,
    metadata: {
      ...metadata,
      correlation_id: metadata.correlation_id || correlationId
    },
    user_profile: body?.user_profile,
    context: body?.context
  };

  audit('guardian.validate.request', {
    correlationId,
    content_length: content.length,
    content_type: metadata.content_type,
    source: metadata.source
  });

  try {
    const result = await validateWithGuardian({ correlationId, input, timeoutMs });
    const latency = Date.now() - start;

    audit('guardian.validate.response', {
      correlationId,
      allowed: !!result.allowed,
      decision: result.decision,
      latency_ms: latency
    });

    return sendJson(res, 200, {
      allowed: !!result.allowed,
      decision: result.decision || null,
      safe_content: result.safe_content || null,
      reasons: result.reasons || [],
      correlationId,
      latency_ms: latency
    });
  } catch (err) {
    const latency = Date.now() - start;
    auditError('guardian.validate.error', {
      correlationId,
      latency_ms: latency,
      message: err?.message || String(err)
    });

    // Fail-closed
    return sendJson(res, 200, {
      allowed: false,
      decision: 'fail_closed_exception',
      safe_content: null,
      reasons: [{ code: 'GUARDIAN_UNAVAILABLE', message: 'Guardián indisponível/erro', severity: 'critical' }],
      correlationId,
      latency_ms: latency
    });
  }
};
