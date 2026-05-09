# Synora Middleware (Vercel) — Guardián Hard Gate (MVP)

API mínima para rodar na Vercel (free) com um endpoint único:

- `POST /middleware/guardian/validate`

E um endpoint de billing (success fee):

- `POST /billing/success-fee/payment_compensated`

E um endpoint de aceite do termo (portal):

- `POST /portal/terms/success-fee/accept`

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

### Billing — payment_compensated (success fee)

```bash
curl -sS -X POST "https://synora-guardian.vercel.app/billing/success-fee/payment_compensated" \
  -H 'content-type: application/json' \
  -d '{
    "agreement_id":"AGR-123",
    "payment_status":"payment_compensated",
    "payment_amount":217,
    "recovered_total_compensated":5217,
    "fee_already_charged":0,
    "hasHumanAssistance":true
  }'
```

> Nota: neste MVP o endpoint calcula `feeAgora` e retorna no campo `data`. A cobrança real do credor (invoice/charge) é integração futura.

### Portal — aceite do termo (success fee)

```bash
curl -sS -X POST "https://synora-guardian.vercel.app/portal/terms/success-fee/accept" \
  -H 'content-type: application/json' \
  -d '{
    "creditor_id":"portal_demo",
    "term_version":"success_fee_v1",
    "accepted_at":"2026-05-07T12:00:00.000Z"
  }'
```

### Stage D — data_access / data_export (MVP)

```bash
curl -sS -X POST "https://synora-guardian.vercel.app/middleware/guardian/validate" \
  -H 'content-type: application/json' \
  -d '{
    "stage":"D",
    "content":"Solicito exportação limitada para contato operacional.",
    "metadata":{
      "tenant_id":"CREDOR-001",
      "purpose":"contato_operacional_pos_acordo",
      "content_type":"application/json",
      "source":"portal",
      "locale":"pt-BR",
      "correlation_id":"REQ-EXAMPLE-001"
    },
    "request":{
      "operation":"export",
      "scope":{
        "fields":["case.id","case.status","debtor.name","contact.whatsappE164"]
      },
      "subject":{ "caseId":"CASE-2805" },
      "retention":"30d",
      "masking":true
    }
  }'
```
