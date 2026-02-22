# tracking-core — White label de rastreamento

Ponte confiável entre funil/site, gateways de pagamento e Meta (Conversions API). Multi-cliente, com eventos do SDK e webhooks (Kiwify e similares).

## O que está pronto

- **POST /events** — Eventos do site (SDK). Header `X-API-Key: api_key_public` do projeto.
- **POST /webhooks/kiwify** — Webhook Kiwify. Autenticação: `?project_key=api_key_secret` ou header `X-Webhook-Secret`.
- **Painel admin** — `GET /painel` (com login em `/login` ou `?key=ADMIN_SECRET`): resumo, projetos, script, webhook, webhook de saída (compras), criar/editar/desativar, ver eventos.
- **Webhook de saída** — Por projeto, opcional: URL chamada em POST quando houver evento Purchase (SDK ou Kiwify). Configure em Editar projeto.
- **Resolução de projeto** — Com banco, `project_id` vem da tabela `projects` (api_key_public / api_key_secret).
- **Meta por projeto** — Se existir linha em `integrations_meta` para o projeto, usa pixel/token de lá; senão usa variáveis de ambiente.
- **SDK** — `sdk/browser-tracker.js` (TrackingCore.createTracker). Eventos: PageView, ViewContent, AddToCart, InitiateCheckout, Purchase, Lead, Contact e scroll (25%, 75%, 100%). Ver **[CONVERSOES.md](CONVERSOES.md)** para exemplos e snippets.
- **Schema** — `sql/schema.sql` + `sql/seed.sql` para primeiro tenant/projeto.

## Checklist para deixar tudo funcionando (depende de você)

1. **Postgres**
   - Ter um banco (local, Railway, Neon, etc.) e a URL de conexão.

2. **Arquivo `.env`** na pasta `tracking-core` (copie de `.env.example`):
   - `DATABASE_URL=postgres://usuario:senha@host:porta/banco`
   - `PORT=4100`
   - `ADMIN_SECRET` — chave para acessar o painel (`/painel?key=...`) e criar projetos (recomendado em produção).
   - `BASE_URL` — ex.: `https://track.ascensaodomentor.com` (usado nos snippets do painel).
   - Opcional (fallback global): `META_PIXEL_ID`, `META_ACCESS_TOKEN`, `META_TEST_EVENT_CODE`

3. **Rodar SQL na ordem**
   - Abra o cliente do Postgres e execute:
     1. Todo o conteúdo de `sql/schema.sql`
     2. Todo o conteúdo de `sql/seed.sql`
   - Se o banco já existia antes: rode `sql/migrations/001_add_webhook_out.sql`, `002_campaign_costs.sql` e `003_enabled_conversions.sql` (webhook de saída, custo por UTM, conversões por projeto).

4. **Projetos**
   - **Pelo painel (recomendado):** acesse `https://sua-api.com/painel?key=SEU_ADMIN_SECRET`, crie projetos e copie script + URL do webhook. Opcional: preencha Pixel ID e Access Token ao criar para Meta por projeto.
   - **Ou pelo seed:** em `sql/seed.sql`, troque `api_key_public` e `api_key_secret`; descomente `integrations_meta` se quiser Meta.

5. **Subir a API**
   - No terminal, na pasta `tracking-core`:
   - `npm install` (se ainda não fez)
   - `npm start`

6. **Testar**
   - **Site/SDK:** use o script exibido no painel (endpoint + apiKey do projeto) ou: `endpoint: 'https://track.ascensaodomentor.com/events'` (ou sua URL), `apiKey: 'pk_live_xxx'`.
   - **Kiwify:** use a URL do webhook exibida no painel ou: `https://track.ascensaodomentor.com/webhooks/kiwify?project_key=sk_live_xxx`.

## Endpoints

| Método | Rota | Autenticação | Uso |
|--------|------|--------------|-----|
| GET | /health | — | Saúde da API (checa banco e Meta) |
| GET | /login | — | Página de login (senha = ADMIN_SECRET) |
| POST | /login | Form senha | Autentica e redireciona para /painel |
| GET | /logout | — | Encerra sessão e redireciona para /login |
| GET | /painel | Cookie ou `?key=ADMIN_SECRET` | Painel: resumo (eventos/compras/valor), projetos, script, webhook, criar/editar/desativar, ver eventos |
| GET | /painel/events/:projectId | Cookie ou `?key=` | Últimos eventos do projeto |
| POST | /api/projects | Header `X-Admin-Key: ADMIN_SECRET` | Criar projeto (nome, Meta opcional) |
| PATCH | /api/projects/:id | Header `X-Admin-Key` | Editar projeto (nome, webhook_out_url, pixel_id, access_token, test_event_code) |
| POST | /api/projects/:id/deactivate | Header `X-Admin-Key` | Desativar projeto |
| POST | /api/projects/:id/activate | Header `X-Admin-Key` | Reativar projeto |
| POST | /api/projects/:id/test-event | Header `X-Admin-Key` | Enviar evento PageView de teste |
| GET | /api/projects/:id/events | Header `X-Admin-Key` | Últimos eventos do projeto (JSON) |
| PUT | /api/campaign-cost | Header `X-Admin-Key` | Salvar custo manual por campanha (utm_source, utm_medium, utm_campaign, cost) para CPA/ROAS |
| POST | /events | Header `X-API-Key: api_key_public` | Eventos do site (SDK) |
| POST | /webhooks/kiwify | Query `project_key=api_key_secret` ou header `X-Webhook-Secret` | Compra aprovada Kiwify |

Com banco configurado, `X-API-Key` é obrigatória em `POST /events`; se inválida ou ausente, retorna 401. Há **rate limit** por minuto em `POST /events` e no webhook Kiwify (padrão 120 e 60 req/min); configurável com `RATE_LIMIT_EVENTS_PER_MIN` e `RATE_LIMIT_WEBHOOK_PER_MIN`.

## SDK (navegador)

Arquivo: `sdk/browser-tracker.js`

```html
<script src="https://track.ascensaodomentor.com/sdk/browser-tracker.js"></script>
<script>
  const tracker = TrackingCore.createTracker({
    endpoint: 'https://track.ascensaodomentor.com/events',
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
