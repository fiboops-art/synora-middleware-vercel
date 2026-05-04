const { audit, auditError } = require('./audit');

/**
 * Integração STUB com OpenClaw.
 *
 * Importante:
 * - Não inventamos endpoints do OpenClaw aqui.
 * - Quando você tiver um contrato/endpoint seguro conhecido, implemente em callGuardianViaGateway().
 *
 * Para testes low-cost (sem OpenClaw exposto):
 * - GUARDIAN_STUB_MODE=allow  -> allowed=true
 * - GUARDIAN_STUB_MODE=deny   -> allowed=false
 */
async function validateWithGuardian({ correlationId, input, timeoutMs }) {
  const stubMode = process.env.GUARDIAN_STUB_MODE;
  if (stubMode === 'allow') return { allowed: true, decision: 'stub_allow' };
  if (stubMode === 'deny') return { allowed: false, decision: 'stub_deny' };

  // Fail-closed quando não configurado.
  const gatewayUrl = process.env.OPENCLAW_GATEWAY_URL;
  const token = process.env.OPENCLAW_GATEWAY_TOKEN;

  if (!gatewayUrl || !token) {
    audit('guardian.not_configured', { correlationId });
    return { allowed: false, decision: 'fail_closed_not_configured' };
  }

  try {
    return await callGuardianViaGateway({ correlationId, input, timeoutMs, gatewayUrl, token });
  } catch (err) {
    auditError('guardian.call_failed', {
      correlationId,
      message: err?.message || String(err),
      name: err?.name || 'Error'
    });
    return { allowed: false, decision: 'fail_closed_error' };
  }
}

async function callGuardianViaGateway({ correlationId, input, timeoutMs, gatewayUrl, token }) {
  // TODO: Ajustar para o contrato real do seu OpenClaw Gateway.
  const payload = {
    agentId: 'guardian',
    correlationId,
    input
  };

  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(new Error('guardian_timeout')), timeoutMs);

  try {
    audit('guardian.call_attempt', { correlationId });

    const res = await fetch(gatewayUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${token}`,
        'x-correlation-id': correlationId
      },
      body: JSON.stringify(payload),
      signal: ac.signal
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`guardian_gateway_http_${res.status}: ${text.slice(0, 300)}`);
    }

    const data = await res.json();

    if (typeof data?.allowed !== 'boolean') {
      throw new Error('guardian_invalid_response_shape');
    }

    audit('guardian.call_success', { correlationId, allowed: data.allowed });
    return data;
  } finally {
    clearTimeout(t);
  }
}

module.exports = { validateWithGuardian };
