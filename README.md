# Synora Middleware (Vercel) — Guardián Hard Gate (MVP)

API mínima para rodar na Vercel (free) com um endpoint único:

- `POST /middleware/guardian/validate`

O body inclui `stage`:

- `A` (onboarding/LGPD)
- `B` (before_send)
- `C` (before_signature)

Por padrão é **fail-closed**: se Guardián não estiver configurado, bloqueia.

## 1) Rodar local

```bash
npm i
npx vercel dev
```

## 2) Deploy na Vercel

1. Suba este repo no GitHub.
2. Vercel → New Project → Import Git Repository.
3. Configure Environment Variables:
   - `GUARDIAN_STUB_MODE=allow` (para testar fluxo sem OpenClaw)
   - `GUARDIAN_TIMEOUT_MS=3500`
   - `ALLOWED_ORIGINS=https://synora-middleware.vercel.app` (CSV)

## 3) Examples (curl)

> Dica: envie `x-correlation-id` para rastreio, ou o serviço gera um.

### Stage A (onboarding/LGPD)

```bash
curl -sS -X POST "http://localhost:3000/middleware/guardian/validate" \
  -H 'content-type: application/json' \
  -H 'x-correlation-id: 11111111-1111-1111-1111-111111111111' \
  -d '{
    "stage":"A",
    "content":"Vamos buscar um acordo possível, sem pressão.",
    "metadata":{
      "content_type":"text/plain",
      "source":"web",
      "locale":"pt-BR",
      "correlation_id":"11111111-1111-1111-1111-111111111111",
      "purpose":"simulacao_acordo"
    },
    "debtor":{
      "full_name":"Maria Silva",
      "document_type":"CPF",
      "document_id":"***.***.***-**"
    }
  }'
```

### Stage B (before_send)

```bash
curl -sS -X POST "http://localhost:3000/middleware/guardian/validate" \
  -H 'content-type: application/json' \
  -d '{
    "stage":"B",
    "content":"Podemos buscar um acordo que caiba no seu orçamento. Você sempre aprova antes de confirmar qualquer acordo.",
    "metadata":{
      "content_type":"text/plain",
      "source":"middleware",
      "locale":"pt-BR",
      "correlation_id":"22222222-2222-2222-2222-222222222222"
    },
    "proposal":{
      "original_debt":5200,
      "negotiated_value":2600,
      "discount":0.5,
      "installments":12,
      "installment_value":217,
      "total_cost":2604,
      "due_dates":["2026-06-10"],
      "late_conditions":"multa e juros conforme contrato",
      "assumptions":"renda estável; manter contas essenciais"
    }
  }'
```

### Stage C (before_signature)

```bash
curl -sS -X POST "http://localhost:3000/middleware/guardian/validate" \
  -H 'content-type: application/json' \
  -d '{
    "stage":"C",
    "content":"Resumo final: proposta neutra e transparente. Você sempre aprova antes de confirmar qualquer acordo.",
    "metadata":{
      "content_type":"text/plain",
      "source":"middleware",
      "locale":"pt-BR",
      "correlation_id":"33333333-3333-3333-3333-333333333333"
    },
    "proposal":{
      "original_debt":980,
      "negotiated_value":600,
      "discount":0.387,
      "installments":6,
      "installment_value":100,
      "total_cost":600,
      "due_dates":["2026-06-10"],
      "late_conditions":"multa e juros conforme contrato",
      "assumptions":"sem comprometer despesas essenciais"
    }
  }'
```

## 4) Integração OpenClaw (TODO)

Para chamar o agente Guardián de verdade, será necessário definir um contrato/endpoint seguro do OpenClaw.
Quando estiver pronto, implemente `callGuardianViaGateway()` em `src/lib/openclawGuardian.js`.

## 5) Chamada pelo front (Netlify)

```js
const res = await fetch('https://SEU-PROJETO.vercel.app/middleware/guardian/validate', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    content: draftText,
    metadata: { content_type: 'message', source: 'netlify', locale: 'pt-BR' },
  })
});
const out = await res.json();
if (out.status !== 'APPROVED' && out.status !== 'APPROVED_WITH_ADJUSTMENTS') {
  // bloquear UI / pedir revisão humana
}
```
