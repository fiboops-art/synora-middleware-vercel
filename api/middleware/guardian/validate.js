const crypto = require('crypto');
const { parseJsonBody, sendJson } = require('../../../src/lib/http');
const { audit, auditError } = require('../../../src/lib/audit');
const { validateWithGuardian } = require('../../../src/lib/openclawGuardian');

const STAGES = new Set(['A', 'B', 'C', 'D']);

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

function stdResponse({ status, risk_score, issues, required_actions, safe_content, audit_log, correlation_id, redactions = [], allowed_scope = null }) {
  return {
    status,
    risk_score,
    issues,
    required_actions,
    safe_content,
    redactions,
    allowed_scope,
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

function isLikelyPiiField(field) {
  const f = String(field || '').toLowerCase();
  return (
    f.includes('cpf') ||
    f.includes('document') ||
    f.includes('email') ||
    f.includes('phone') ||
    f.includes('whatsapp')
  );
}

function maskFieldValue(field) {
  const f = String(field || '').toLowerCase();
  if (f.includes('email')) return 'mask_email';
  if (f.includes('whatsapp') || f.includes('phone')) return 'mask_phone';
  if (f.includes('cpf') || f.includes('document')) return 'mask_document';
  return 'mask';
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
  const request = body?.request;

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

  // Stage D: data_access / data_export
  if (stage === 'D') {
    decisionPath.push('stage_D');

    // Required fields
    const missingD = requireFields(body, [
      'metadata.tenant_id',
      'metadata.purpose',
      'request.scope',
      'request.subject',
      'request.retention',
      'request.masking',
    ]);

    if (missingD.length) {
      rulesTriggered.push('stageD_missing_fields');
      for (const f of missingD) issues.push(issue('MISSING_FIELD', `Campo obrigatório ausente: ${f}`, 'high', f));
      requiredActions.push('Enviar payload Stage D completo (tenant_id, purpose, scope, subject, retention, masking)');
      riskScore = Math.max(riskScore, 95);
    }

    // Basic tenant isolation: require tenant_id (we can't validate tenant match yet in MVP)
    if (!metadata?.tenant_id) {
      rulesTriggered.push('stageD_missing_tenant_id');
      issues.push(issue('MISSING_TENANT_ID', 'metadata.tenant_id é obrigatório (isolamento de tenant)', 'critical', 'metadata.tenant_id'));
      requiredActions.push('Informar metadata.tenant_id');
      riskScore = Math.max(riskScore, 100);
    }

    // Retention must be non-empty (e.g. 30d)
    if (request && typeof request.retention === 'string' && !request.retention.trim()) {
      rulesTriggered.push('stageD_retention_missing');
      issues.push(issue('RETENTION_MISSING', 'request.retention é obrigatório (prazo de retenção)', 'high', 'request.retention'));
      requiredActions.push('Definir request.retention (ex.: "30d")');
      riskScore = Math.max(riskScore, 95);
    }

    // Mass export heuristic: aggregation without single-subject identifiers and broad scope.
    const subject = request?.subject;
    const hasSubjectId = !!(subject?.caseId || subject?.customerId || subject?.debtId || subject?.contractId);
    const fields = request?.scope?.fields;
    const fieldCount = Array.isArray(fields) ? fields.length : 0;
    const isAggregate = !!subject?.aggregate || !!subject?.all || !hasSubjectId;
    const justification = request?.justification;
    const approver = request?.approver;
    const hasJustification = !!justification && typeof justification === 'object';
    const hasApprover = !!approver && typeof approver === 'object';

    const justificationMissing = [];
    if (isAggregate) {
      // If aggregate, require structured justification + approver + masking=true
      if (!hasJustification) {
        justificationMissing.push('request.justification');
      } else {
        for (const f of ['business_reason', 'legal_basis', 'data_minimization', 'audience']) {
          if (!justification?.[f]) justificationMissing.push(`request.justification.${f}`);
        }
      }
      if (!hasApprover) {
        justificationMissing.push('request.approver');
      } else {
        for (const f of ['approver_id', 'approver_role']) {
          if (!approver?.[f]) justificationMissing.push(`request.approver.${f}`);
        }
      }

      if (request?.masking !== true) {
        justificationMissing.push('request.masking');
      }

      // Also require scope without raw PII fields for aggregate
      const piiFieldsAgg = Array.isArray(fields) ? fields.filter(isLikelyPiiField) : [];
      if (piiFieldsAgg.length) {
        rulesTriggered.push('stageD_aggregate_contains_pii');
        issues.push(issue('RAW_PII_REQUEST', 'Export agregado não pode incluir campos de PII (mesmo com masking) — use métricas/IDs', 'critical', 'request.scope.fields'));
        requiredActions.push('Remover PII do scope.fields para export agregado');
        riskScore = Math.max(riskScore, 100);
      }

      if (justificationMissing.length) {
        rulesTriggered.push('stageD_mass_export');
        issues.push(issue('EXPORT_MASS_REQUEST', 'Pedido agregado/em massa exige justificativa formal + aprovar (Stage D)', 'critical', 'request.subject'));
        for (const f of justificationMissing) {
          issues.push(issue('MISSING_FIELD', `Campo obrigatório ausente para agregação: ${f}`, 'high', f));
        }
        requiredActions.push('Para export agregado: preencher request.justification + request.approver + masking=true e remover PII do scope');
        riskScore = Math.max(riskScore, 100);
      } else {
        // Aggregate allowed (still may be approved with redactions for any non-PII fields)
        rulesTriggered.push('stageD_aggregate_approved_with_justification');
        riskScore = Math.max(riskScore, 25);
      }
    } else {
      // Non-aggregate broad scope (still caution)
      if (fieldCount >= 10) {
        rulesTriggered.push('stageD_scope_broad');
        requiredActions.push('Recomendação: reduzir scope.fields ao mínimo necessário');
        riskScore = Math.max(riskScore, 35);
      }
    }

    // Raw PII request handling
    const masking = request?.masking;
    const piiFields = Array.isArray(fields) ? fields.filter(isLikelyPiiField) : [];
    const redactions = [];
    let allowed_scope = null;

    if (piiFields.length) {
      if (masking === false) {
        rulesTriggered.push('stageD_raw_pii_request');
        issues.push(issue('RAW_PII_REQUEST', 'Solicitação de PII cru sem masking (Stage D)', 'critical', 'request.masking'));
        requiredActions.push('Definir request.masking=true ou remover campos de PII do escopo');
        riskScore = Math.max(riskScore, 100);
      } else {
        rulesTriggered.push('stageD_pii_with_masking');
        for (const f of piiFields) {
          redactions.push({ field: f, rule: 'mask', reason: `Minimização e anti-vazamento (${maskFieldValue(f)})` });
        }
        allowed_scope = { fields: Array.isArray(fields) ? fields : [] };
        riskScore = Math.max(riskScore, 20);
      }
    } else {
      allowed_scope = { fields: Array.isArray(fields) ? fields : [] };
    }

    if (issues.length) {
      const out = stdResponse({
        status: 'BLOCKED',
        risk_score: Math.max(riskScore, 90),
        issues,
        required_actions: requiredActions,
        safe_content: null,
        redactions,
        allowed_scope,
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

    // Default: approve with redactions if any
    const out = stdResponse({
      status: redactions.length ? 'APPROVED_WITH_ADJUSTMENTS' : 'APPROVED',
      risk_score: redactions.length ? Math.max(10, riskScore) : 0,
      issues: [],
      required_actions: redactions.length ? ['Exportar com masking (redactions) aplicado'] : [],
      safe_content: null,
      redactions,
      allowed_scope,
      audit_log: { rules_triggered: rulesTriggered, decision_path: decisionPath },
      correlation_id,
    });

    audit('guardian.validate.audit', {
      correlationId: correlation_id,
      rules_triggered: out.audit_log.rules_triggered,
    });

    return sendJson(res, 200, out);
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
    request,
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
