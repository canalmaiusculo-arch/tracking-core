# tracking-core — White label de rastreamento

Ponte confiável entre funil/site, gateways de pagamento e Meta (Conversions API). Multi-cliente, com eventos do SDK e webhooks (Kiwify e similares).

## O que está pronto

- **POST /events** — Eventos do site (SDK). Header `X-API-Key: api_key_public` do projeto.
- **POST /webhooks/kiwify** — Webhook Kiwify. Autenticação: `?project_key=api_key_secret` ou header `X-Webhook-Secret`.
- **Resolução de projeto** — Com banco, `project_id` vem da tabela `projects` (api_key_public / api_key_secret).
- **Meta por projeto** — Se existir linha em `integrations_meta` para o projeto, usa pixel/token de lá; senão usa variáveis de ambiente.
- **SDK** — `sdk/browser-tracker.js` (TrackingCore.createTracker).
- **Schema** — `sql/schema.sql` + `sql/seed.sql` para primeiro tenant/projeto.

## Checklist para deixar tudo funcionando (depende de você)

1. **Postgres**
   - Ter um banco (local, Railway, Neon, etc.) e a URL de conexão.

2. **Arquivo `.env`** na pasta `tracking-core` (copie de `.env.example`):
   - `DATABASE_URL=postgres://usuario:senha@host:porta/banco`
   - `PORT=4100`
   - Opcional (fallback global): `META_PIXEL_ID`, `META_ACCESS_TOKEN`, `META_TEST_EVENT_CODE`

3. **Rodar SQL na ordem**
   - Abra o cliente do Postgres e execute:
     1. Todo o conteúdo de `sql/schema.sql`
     2. Todo o conteúdo de `sql/seed.sql`

4. **Ajustar o seed (ou inserir manualmente)**
   - Em `sql/seed.sql`, troque `api_key_public` e `api_key_secret` por chaves que você vai usar (ex.: `pk_live_xxx`, `sk_live_xxx`).
   - Se quiser Meta por projeto: descomente o `INSERT INTO integrations_meta` no seed e preencha `pixel_id` e `access_token` do projeto.

5. **Subir a API**
   - No terminal, na pasta `tracking-core`:
   - `npm install` (se ainda não fez)
   - `npm start`

6. **Testar**
   - **Site/SDK:** no seu HTML, use o SDK com `apiKey: 'pk_live_xxx'` (o mesmo `api_key_public` do projeto) e `endpoint: 'http://localhost:4100/events'` (ou a URL do servidor).
   - **Kiwify:** na Kiwify, configure o webhook com URL `https://sua-api.com/webhooks/kiwify?project_key=sk_live_xxx` (use o `api_key_secret` do projeto). Ou envie o secret no header `X-Webhook-Secret`.

## Endpoints

| Método | Rota | Autenticação | Uso |
|--------|------|--------------|-----|
| GET | /health | — | Saúde da API |
| POST | /events | Header `X-API-Key: api_key_public` | Eventos do site (SDK) |
| POST | /webhooks/kiwify | Query `project_key=api_key_secret` ou header `X-Webhook-Secret` | Compra aprovada Kiwify |

Com banco configurado, `X-API-Key` é obrigatória em `POST /events`; se inválida ou ausente, retorna 401.

## SDK (navegador)

Arquivo: `sdk/browser-tracker.js`

```html
<script src="https://sua-api.com/sdk/browser-tracker.js"></script>
<script>
  const tracker = TrackingCore.createTracker({
    endpoint: 'https://sua-api.com/events',
    apiKey: 'pk_live_xxxxxxxxxxxxxxxx'
  });
  tracker.trackPageView();
  tracker.trackPurchase({ order_id: 'PEDIDO123', value: 199.9, currency: 'BRL' });
</script>
```

## Deploy em servidor

- Coloque a API em um host (Railway, Render, Fly.io, VPS, etc.).
- Defina as variáveis de ambiente no painel do serviço (ou `.env` no servidor).
- Use a URL pública da API no SDK (`endpoint`) e na configuração do webhook da Kiwify.
- Se servir o SDK pelo mesmo domínio, exponha a pasta `sdk` como estático (ex.: `https://sua-api.com/sdk/browser-tracker.js`).

Quando tudo estiver configurado (Postgres, seed com suas chaves, Meta opcional), a white label fica pronta para receber eventos do site e da Kiwify e repassar ao Meta.
