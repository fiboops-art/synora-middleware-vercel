const crypto = require('crypto');
const { parseJsonBody, sendJson } = require('../../../../src/lib/http');
const { audit, auditError } = require('../../../../src/lib/audit');

function getAllowedOrigins() {
  const raw = (process.env.ALLOWED_ORIGINS || '').trim();
  if (!raw) return [];
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function setCors(req, res) {
  const origins = getAllowedOrigins();
  const origin = req.headers.origin;
  const isProd = process.env.NODE_ENV === 'production';

  if (!isProd && origins.length === 0) {
    res.setHeader('access-control-allow-origin', '*');
  } else if (origin && origins.includes(origin)) {
    res.setHeader('access-control-allow-origin', origin);
    res.setHeader('vary', 'origin');
  }

  res.setHeader('access-control-allow-headers', 'content-type, x-correlation-id, authorization');
  res.setHeader('access-control-allow-methods', 'POST, OPTIONS');
}

function issue(code, message, severity = 'medium', field = null) {
  return { code, message, severity, field };
}

function std({ status, risk_score, issues, required_actions, safe_content, audit_log, correlation_id, data = null }) {
  return {
    status,
    risk_score,
    issues,
    required_actions,
    safe_content,
    audit_log,
    correlation_id,
    data,
  };
}

module.exports = async function handler(req, res) {
  const start = Date.now();
  const correlationId = req.headers['x-correlation-id'] || crypto.randomUUID();
  res.setHeader('x-correlation-id', correlationId);
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.end();

  if (req.method !== 'POST') {
    return sendJson(
      res,
      405,
      std({
        status: 'BLOCKED',
        risk_score: 100,
        issues: [issue('METHOD_NOT_ALLOWED', 'Método não permitido', 'high')],
        required_actions: [],
        safe_content: null,
        audit_log: { rules_triggered: ['method_not_allowed'], decision_path: ['http_guard'] },
        correlation_id: correlationId,
      }),
    );
  }

  let body;
  try {
    body = await parseJsonBody(req);
  } catch {
    return sendJson(
      res,
      400,
      std({
        status: 'BLOCKED',
        risk_score: 100,
        issues: [issue('INVALID_JSON', 'Body JSON inválido', 'high')],
        required_actions: ['Enviar JSON válido'],
        safe_content: null,
        audit_log: { rules_triggered: ['invalid_json'], decision_path: ['parse_body'] },
        correlation_id: correlationId,
      }),
    );
  }

  const creditor_id = body?.creditor_id;
  const term_version = body?.term_version;
  const accepted_at = body?.accepted_at;

  const issues = [];
  const rules = [];
  const path = ['terms_accept'];

  if (!creditor_id) {
    rules.push('missing_creditor_id');
    issues.push(issue('MISSING_FIELD', 'creditor_id é obrigatório', 'high', 'creditor_id'));
  }
  if (!term_version) {
    rules.push('missing_term_version');
    issues.push(issue('MISSING_FIELD', 'term_version é obrigatório', 'high', 'term_version'));
  }
  if (!accepted_at) {
    rules.push('missing_accepted_at');
    issues.push(issue('MISSING_FIELD', 'accepted_at é obrigatório (ISO8601)', 'high', 'accepted_at'));
  }

  if (issues.length) {
    return sendJson(
      res,
      200,
      std({
        status: 'BLOCKED',
        risk_score: 90,
        issues,
        required_actions: ['Preencher campos obrigatórios e reenviar'],
        safe_content: null,
        audit_log: { rules_triggered: rules, decision_path: path },
        correlation_id: correlationId,
      }),
    );
  }

  try {
    const latency = Date.now() - start;

    audit('portal.terms.success_fee.accepted', {
      correlationId,
      creditor_id,
      term_version,
      accepted_at,
      latency_ms: latency,
      rules_triggered: ['term_accepted'],
    });

    return sendJson(
      res,
      200,
      std({
        status: 'APPROVED',
        risk_score: 0,
        issues: [],
        required_actions: [],
        safe_content: null,
        audit_log: { rules_triggered: ['term_accepted'], decision_path: path },
        correlation_id: correlationId,
        data: { creditor_id, term_version, accepted_at },
      }),
      { 'x-latency-ms': String(latency) },
    );
  } catch (err) {
    const latency = Date.now() - start;
    auditError('portal.terms.accept.error', {
      correlationId,
      latency_ms: latency,
      message: err?.message || String(err),
    });

    return sendJson(
      res,
      200,
      std({
        status: 'BLOCKED',
        risk_score: 100,
        issues: [issue('FAIL_CLOSED', 'Erro interno (fail-closed)', 'critical')],
        required_actions: ['Tentar novamente ou encaminhar para revisão humana'],
        safe_content: null,
        audit_log: { rules_triggered: ['fail_closed_exception'], decision_path: [...path, 'exception'] },
        correlation_id: correlationId,
      }),
    );
  }
};

