const crypto = require('crypto');
const { parseJsonBody, sendJson } = require('../../../src/lib/http');
const { audit, auditError } = require('../../../src/lib/audit');
const { computeSuccessFee } = require('../../../src/lib/successFee');

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
    // fail-closed
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

  const rules = [];
  const path = ['payment_compensated'];
  const issues = [];
  const required = [];

  const agreement_id = body?.agreement_id;
  const payment_amount = Number(body?.payment_amount);
  const payment_status = body?.payment_status;
  const recovered_total_compensated = Number(body?.recovered_total_compensated);
  const fee_already_charged = Number(body?.fee_already_charged || 0);
  const hasHumanAssistance = !!body?.hasHumanAssistance;

  if (!agreement_id) {
    rules.push('missing_agreement_id');
    issues.push(issue('MISSING_FIELD', 'agreement_id é obrigatório', 'high', 'agreement_id'));
  }
  if (!Number.isFinite(payment_amount) || payment_amount <= 0) {
    rules.push('invalid_payment_amount');
    issues.push(issue('INVALID_FIELD', 'payment_amount deve ser número > 0', 'high', 'payment_amount'));
  }
  if (payment_status !== 'payment_compensated') {
    rules.push('invalid_payment_status');
    issues.push(issue('INVALID_FIELD', 'payment_status deve ser "payment_compensated"', 'high', 'payment_status'));
  }
  if (!Number.isFinite(recovered_total_compensated) || recovered_total_compensated < 0) {
    rules.push('invalid_recovered_total');
    issues.push(issue('INVALID_FIELD', 'recovered_total_compensated deve ser número >= 0', 'high', 'recovered_total_compensated'));
  }

  if (issues.length) {
    return sendJson(
      res,
      200,
      std({
        status: 'BLOCKED',
        risk_score: 90,
        issues,
        required_actions: required.length ? required : ['Corrigir payload e reenviar'],
        safe_content: null,
        audit_log: { rules_triggered: rules, decision_path: path },
        correlation_id: correlationId,
      }),
    );
  }

  try {
    const valorRecuperado = recovered_total_compensated; // acumulado por acordo
    const calc = computeSuccessFee({
      valorRecuperado,
      feeJaCobrado: fee_already_charged,
      hasHumanAssistance,
    });

    // “Cobrar” é integração futura — aqui devolvemos feeAgora.
    rules.push('success_fee_computed');

    const latency = Date.now() - start;
    audit('billing.success_fee.payment_compensated', {
      correlationId,
      agreement_id,
      valorRecuperado: calc.valorRecuperado,
      rate: calc.rate,
      feeDevido: calc.feeDevido,
      feeJaCobrado: calc.feeJaCobrado,
      feeAgora: calc.feeAgora,
      latency_ms: latency,
      rules_triggered: rules,
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
        audit_log: { rules_triggered: rules, decision_path: path },
        correlation_id: correlationId,
        data: {
          agreement_id,
          payment_amount,
          payment_status,
          hasHumanAssistance,
          ...calc,
        },
      }),
      { 'x-latency-ms': String(latency) },
    );
  } catch (err) {
    const latency = Date.now() - start;
    auditError('billing.success_fee.error', {
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

