function clamp(n, a, b) {
  return Math.max(a, Math.min(b, n));
}

function bandRate(valorRecuperado) {
  const v = Number(valorRecuperado || 0);
  if (v <= 5000) return 0.09;
  if (v <= 20000) return 0.07;
  return 0.05;
}

/**
 * Success fee (credor) — banda aplicada sobre o total inteiro do acordo.
 *
 * Regras:
 * - valorRecuperado = soma de pagamentos COMPENSADOS
 * - rate por faixa (sobre o valorRecuperado inteiro)
 * - +1% se hasHumanAssistance
 * - feeAgora = max(0, feeDevido - feeJaCobrado)
 */
function computeSuccessFee({ valorRecuperado, feeJaCobrado = 0, hasHumanAssistance = false }) {
  const recovered = Math.max(0, Number(valorRecuperado || 0));
  const already = Math.max(0, Number(feeJaCobrado || 0));

  let rate = bandRate(recovered);
  if (hasHumanAssistance) rate += 0.01;
  rate = clamp(rate, 0, 0.2);

  const feeDevido = recovered * rate;
  const feeAgora = Math.max(0, feeDevido - already);

  return {
    valorRecuperado: recovered,
    rate,
    feeDevido,
    feeJaCobrado: already,
    feeAgora,
  };
}

module.exports = { computeSuccessFee };

