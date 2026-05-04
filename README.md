# Synora Middleware (Vercel) — Guardián Hard Gate (MVP)

API mínima para rodar na Vercel (free) com um endpoint único:

- `POST /middleware/guardian/validate`

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

Depois do deploy, teste:

```bash
curl -X POST "https://SEU-PROJETO.vercel.app/middleware/guardian/validate" \
  -H "content-type: application/json" \
  -d '{"content":"texto teste","metadata":{"content_type":"message","source":"netlify"}}'
```

## 3) Integração OpenClaw (TODO)

Para chamar o agente Guardián de verdade, será necessário definir um contrato/endpoint seguro do OpenClaw.
Quando estiver pronto, implemente `callGuardianViaGateway()` em `src/lib/openclawGuardian.js`.

## 4) Chamada pelo front (Netlify)

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
if (!out.allowed) {
  // bloquear UI / pedir revisão humana
}
```
