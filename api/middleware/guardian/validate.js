const crypto = require('crypto');
const { parseJsonBody, sendJson } = require('../../../src/lib/http');
const { audit, auditError } = require('../../../src/lib/audit');
const { validateWithGuardian } = require('../../../src/lib/openclawGuardian');

const STAGES = new Set(['A', 'B', 'C']);

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

function stdResponse({ status, risk_score, issues, required_actions, safe_content, audit_log, correlation_id }) {
  return {
    status,
    risk_score,
    issues,
    required_actions,
    safe_content,
    audit_log,
    correlation_id,
  };
}

function issue(code, message, severity = 'medium', field = null) {
  return { code, message, severity, field };
}

function detectSensitive(content) {
  const hits = [];
  const s = String(content || '');

  // CPF (000.000.000-00 or 11 digits)
  if (/\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/.test(s) || /\b\d{11}\b/.test(s)) hits.push('cpf');
  // Cartão (13-19 digits, very naive)
  if (/\b\d{13,19}\b/.test(s)) hits.push('card');
  // Email
  if (/\b[^\s@]+@[^\s@]+\.[^\s@]+\b/.test(s)) hits.push('email');
  // Telefone BR
  if (/\b\+?55\s?\(?\d{2}\)?\s?9?\d{4}-?\d{4}\b/.test(s)) hits.push('phone');

  return Array.from(new Set(hits));
}

function maskSensitive(content) {
  let s = String(content || '');
  s = s.replace(/\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g, '***.***.***-**');
  s = s.replace(/\b\d{11}\b/g, '***********');
  s = s.replace(/\b\d{13,19}\b/g, (m) => `${m.slice(0, 2)}************${m.slice(-2)}`);
  s = s.replace(/\b([^\s@])[^\s@]*@([^\s@]+)\b/g, '$1***@$2');
  s = s.replace(/\b\+?55\s?\(?\d{2}\)?\s?9?\d{4}-?\d{4}\b/g, '+55 ** *****-****');
  return s;
}

function containsCoercion(content) {
  const s = String(content || '').toLowerCase();
  const patterns = [
    /se você não pagar/, /última chance/, /vai ser processad/, /penhora/, /bloqueio/, /negativad/, /protesto/,
    /ameaç/, /cobrança/, /cobrador/, /pague agora/, /sem escolha/, /você é culpado/, /inadimplente/,
    /promoç/, /oferta imperdível/, /só hoje/, /garantia de aprovação/,
  ];
  return patterns.some((re) => re.test(s));
}

function requireFields(obj, paths) {
  const missing = [];
  for (const p of paths) {
    const parts = p.split('.');
    let cur = obj;
    for (const key of parts) {
      if (!cur || typeof cur !== 'object' || !(key in cur)) {
        missing.push(p);
        cur = null;
        break;
      }
      cur = cur[key];
    }
    if (cur === '' || cur === null || cur === undefined) {
      // already counted if missing; but also treat empty as missing
      if (!missing.includes(p)) missing.push(p);
    }
  }
  return missing;
}

function numericClose(a, b, relTol = 0.02) {
  const x = Number(a);
  const y = Number(b);
  if (!Number.isFinite(x) || !Number.isFinite(y)) return false;
  const denom = Math.max(1, Math.abs(y));
  return Math.abs(x - y) / denom <= relTol;
}

module.exports = async function handler(req, res) {
  const start = Date.now();
  const correlationId = req.headers['x-correlation-id'] || crypto.randomUUID();
  res.setHeader('x-correlation-id', correlationId);

  // CORS via allowlist (env ALLOWED_ORIGINS). Se vazio, '*' apenas em dev.
  setCors(req, res);

  if (req.method === 'OPTIONS') return res.end();

  if (req.method !== 'POST') {
    return sendJson(res, 405, stdResponse({
      status: 'BLOCKED',
      risk_score: 100,
      issues: [issue('METHOD_NOT_ALLOWED', 'Método não permitido', 'high')],
      required_actions: [],
      safe_content: null,
      audit_log: { rules_triggered: ['method_not_allowed'], decision_path: ['http_guard'] },
      correlation_id: correlationId,
    }));
  }

  let body;
  try {
    body = await parseJsonBody(req);
  } catch (err) {
    // Fail-closed
    const out = stdResponse({
      status: 'BLOCKED',
      risk_score: 100,
      issues: [issue('INVALID_JSON', 'Body JSON inválido', 'high')],
      required_actions: ['Enviar JSON válido'],
      safe_content: null,
      audit_log: { rules_triggered: ['invalid_json'], decision_path: ['parse_body'] },
      correlation_id: correlationId,
    });
    return sendJson(res, err.statusCode || 400, out);
  }

  const stage = body?.stage;
  const content = body?.content;
  const metadata = body?.metadata;
  const proposal = body?.proposal;
  const debtor = body?.debtor;

  const rulesTriggered = [];
  const decisionPath = [];
  const issues = [];
  const requiredActions = [];
  let riskScore = 0;
  let safeContent = null;

  const correlation_id = metadata?.correlation_id || correlationId;

  // stage validation
  if (!STAGES.has(stage)) {
    rulesTriggered.push('invalid_stage');
    issues.push(issue('INVALID_STAGE', 'stage deve ser "A", "B" ou "C"', 'high', 'stage'));
  }

  // shared minimal input
  if (typeof content !== 'string' || !content.trim()) {
    rulesTriggered.push('missing_content');
    issues.push(issue('MISSING_CONTENT', 'content é obrigatório', 'high', 'content'));
  }
  if (!metadata || typeof metadata !== 'object') {
    rulesTriggered.push('missing_metadata');
    issues.push(issue('MISSING_METADATA', 'metadata é obrigatório', 'high', 'metadata'));
  }

  // Stage A: onboarding/LGPD minimum schema
  if (stage === 'A') {
    decisionPath.push('stage_A');
    const missingMeta = requireFields(body, [
      'metadata.content_type',
      'metadata.source',
      'metadata.locale',
      'metadata.correlation_id',
    ]);
    if (missingMeta.length) {
      rulesTriggered.push('stageA_missing_metadata');
      for (const f of missingMeta) issues.push(issue('MISSING_FIELD', `Campo obrigatório ausente: ${f}`, 'high', f));
    }

    const missingDebtor = requireFields(body, [
      'debtor.full_name',
      'debtor.document_type',
      'debtor.document_id',
    ]);
    if (missingDebtor.length) {
      rulesTriggered.push('stageA_missing_debtor');
      for (const f of missingDebtor) issues.push(issue('MISSING_FIELD', `Campo obrigatório ausente: ${f}`, 'high', f));
      requiredActions.push('Preencher dados mínimos do devedor');
    }

    // Sensitive data handling: block if sensitive present without purpose
    const sens = detectSensitive(content);
    if (sens.length) {
      const purpose = metadata?.purpose || metadata?.finalidade;
      if (!purpose) {
        rulesTriggered.push('stageA_sensitive_without_purpose');
        issues.push(issue('SENSITIVE_DATA_WITHOUT_PURPOSE', 'Conteúdo contém dados sensíveis sem finalidade explícita', 'high', 'metadata.purpose'));
        requiredActions.push('Informar metadata.purpose (finalidade) ou remover dados sensíveis do conteúdo');
        riskScore = Math.max(riskScore, 90);
      } else {
        // allow with adjustments (mask)
        rulesTriggered.push('stageA_sensitive_masked');
        safeContent = maskSensitive(content);
        riskScore = Math.max(riskScore, 30);
      }
    }
  }

  // Stage B: before_send
  if (stage === 'B') {
    decisionPath.push('stage_B');
    const missingProposal = requireFields(body, [
      'proposal.original_debt',
      'proposal.negotiated_value',
      'proposal.discount',
      'proposal.installments',
      'proposal.installment_value',
      'proposal.total_cost',
      'proposal.due_dates',
      'proposal.late_conditions',
      'proposal.assumptions',
    ]);
    if (missingProposal.length) {
      rulesTriggered.push('stageB_missing_proposal');
      for (const f of missingProposal) issues.push(issue('MISSING_FIELD', `Campo obrigatório ausente: ${f}`, 'high', f));
      requiredActions.push('Enviar objeto proposal completo antes do envio ao cliente');
      riskScore = Math.max(riskScore, 80);
    }

    if (containsCoercion(content)) {
      rulesTriggered.push('stageB_coercive_language');
      issues.push(issue('COERCIVE_LANGUAGE', 'Linguagem coercitiva/promoção/ameaça detectada — ajuste para tom neutro', 'high', 'content'));
      requiredActions.push('Reescrever conteúdo para linguagem humana, neutra e não ameaçadora');
      riskScore = Math.max(riskScore, 95);
    }
  }

  // Stage C: before_signature
  if (stage === 'C') {
    decisionPath.push('stage_C');
    const missingProposal = requireFields(body, [
      'proposal.original_debt',
      'proposal.negotiated_value',
      'proposal.discount',
      'proposal.installments',
      'proposal.installment_value',
      'proposal.total_cost',
      'proposal.due_dates',
      'proposal.late_conditions',
      'proposal.assumptions',
    ]);
    if (missingProposal.length) {
      rulesTriggered.push('stageC_missing_proposal');
      for (const f of missingProposal) issues.push(issue('MISSING_FIELD', `Campo obrigatório ausente: ${f}`, 'high', f));
      requiredActions.push('Enviar objeto proposal completo antes da assinatura');
      riskScore = Math.max(riskScore, 80);
    }

    if (proposal && Number.isFinite(Number(proposal.installments)) && Number.isFinite(Number(proposal.installment_value)) && Number.isFinite(Number(proposal.total_cost))) {
      const approx = Number(proposal.installment_value) * Number(proposal.installments);
      if (!numericClose(Number(proposal.total_cost), approx, 0.03)) {
        rulesTriggered.push('stageC_numeric_inconsistency');
        issues.push(issue('NUMERIC_INCONSISTENCY', 'total_cost inconsistente com installment_value * installments', 'high', 'proposal.total_cost'));
        requiredActions.push('Corrigir consistência numérica da proposta antes da assinatura');
        riskScore = Math.max(riskScore, 90);
      }
    }

    if (containsCoercion(content)) {
      rulesTriggered.push('stageC_coercive_language');
      issues.push(issue('COERCIVE_LANGUAGE', 'Texto final contém linguagem coercitiva/promoção/ameaça — deve ser neutro', 'high', 'content'));
      requiredActions.push('Reescrever texto final para tom neutro e respeitoso');
      riskScore = Math.max(riskScore, 95);
    }
  }

  // If any issues at this point => BLOCKED (fail-closed)
  if (issues.length) {
    const out = stdResponse({
      status: 'BLOCKED',
      risk_score: Math.max(riskScore, 80),
      issues,
      required_actions: requiredActions,
      safe_content: safeContent,
      audit_log: { rules_triggered: rulesTriggered, decision_path: decisionPath },
      correlation_id,
    });

    audit('guardian.validate.decision', {
      correlationId: correlation_id,
      status: out.status,
      rules_triggered: rulesTriggered,
    });

    return sendJson(res, 200, out);
  }

  const timeoutMs = Number(process.env.GUARDIAN_TIMEOUT_MS || 3500);

  const input = {
    content,
    metadata: {
      ...metadata,
      correlation_id
    },
    stage,
    debtor,
    proposal,
    user_profile: body?.user_profile,
    context: body?.context
  };

  audit('guardian.validate.request', {
    correlationId: correlation_id,
    content_length: content.length,
    content_type: metadata.content_type,
    source: metadata.source
  });

  try {
    const result = await validateWithGuardian({ correlationId, input, timeoutMs });
    const latency = Date.now() - start;

    // Map guardian result to standard response.
    // Expected guardian response: { allowed:boolean, decision?:string, safe_content?:string, reasons?:array }
    const allowed = !!result.allowed;
    const gReasons = Array.isArray(result.reasons) ? result.reasons : [];
    const gDecision = result.decision || null;

    if (!allowed) rulesTriggered.push(gDecision || 'guardian_denied');
    if (allowed && (result.safe_content && result.safe_content !== content)) rulesTriggered.push('guardian_safe_content');

    const status = allowed ? (result.safe_content ? 'APPROVED_WITH_ADJUSTMENTS' : 'APPROVED') : 'BLOCKED';
    const mappedIssues = allowed
      ? []
      : gReasons.map((r) => issue(r.code || 'GUARDIAN_BLOCK', r.message || 'Bloqueado pelo guardian', r.severity || 'high', r.field || null));

    const out = stdResponse({
      status,
      risk_score: allowed ? 0 : 95,
      issues: mappedIssues,
      required_actions: allowed ? [] : ['Revisar conteúdo e reenviar'],
      safe_content: result.safe_content || safeContent || null,
      audit_log: { rules_triggered: rulesTriggered, decision_path: [...decisionPath, 'guardian'] },
      correlation_id,
    });

    audit('guardian.validate.response', {
      correlationId: correlation_id,
      status: out.status,
      decision: gDecision,
      latency_ms: latency
    });

    // Audit log (console) com correlationId e rules_triggered.
    audit('guardian.validate.audit', {
      correlationId: correlation_id,
      rules_triggered: out.audit_log.rules_triggered
    });

    return sendJson(res, 200, out, { 'x-latency-ms': String(latency) });
  } catch (err) {
    const latency = Date.now() - start;
    auditError('guardian.validate.error', {
      correlationId: correlation_id,
      latency_ms: latency,
      message: err?.message || String(err)
    });

    // Fail-closed
    const out = stdResponse({
      status: 'BLOCKED',
      risk_score: 100,
      issues: [issue('GUARDIAN_UNAVAILABLE', 'Guardián indisponível/erro (fail-closed)', 'critical')],
      required_actions: ['Tentar novamente mais tarde ou encaminhar para revisão humana'],
      safe_content: null,
      audit_log: { rules_triggered: [...rulesTriggered, 'fail_closed_exception'], decision_path: [...decisionPath, 'exception'] },
      correlation_id,
    });

    audit('guardian.validate.audit', {
      correlationId: correlation_id,
      rules_triggered: out.audit_log.rules_triggered
    });

    return sendJson(res, 200, out, { 'x-latency-ms': String(latency) });
  }
};
