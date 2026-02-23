# Colocar a API em produção (deploy)

Com a API em um servidor na nuvem, qualquer pessoa pode acessar e a Kiwify consegue enviar webhooks. O passo a passo abaixo usa o **Railway** (grátis para começar).

---

## 1. Colocar o código no GitHub

1. Crie uma conta em **https://github.com** (se ainda não tiver).
2. Crie um **repositório novo** (New repository). Nome sugerido: `tracking-core`. Não marque "Add README".
3. No seu PC, abra o terminal na pasta do projeto:
   ```powershell
   cd C:\projetos\meu-primeiro-aios\meu-primeiro-aios\tracking-core
   ```
4. Inicialize o Git e envie o código (troque `SEU_USUARIO` pelo seu usuário do GitHub):
   ```powershell
   git init
   git add .
   git commit -m "tracking-core white label"
   git branch -M main
   git remote add origin https://github.com/canalmaiusculo-arch/tracking-core.git
   git push -u origin main
   ```
   Se pedir usuário/senha, use um **Personal Access Token** do GitHub (Settings → Developer settings → Personal access tokens) em vez da senha da conta.

**Importante:** não suba o `.env` para o GitHub (ele tem sua senha do banco). Crie um arquivo `.gitignore` na pasta `tracking-core` com uma linha:
   ```
   .env
   ```
   Depois rode de novo: `git add .` e `git commit -m "add gitignore"` e `git push`.

---

## 2. Criar projeto no Railway

1. Acesse **   ** e entre com o GitHub.
2. Clique em **New Project**.
3. Escolha **Deploy from GitHub repo** e selecione o repositório `tracking-core`.
4. O Railway vai detectar que é Node e fazer o deploy. Se pedir **root directory**, deixe em branco ou `./`.
5. Clique no projeto e depois no **serviço** (o quadrado que apareceu). Vá em **Variables** (Variáveis).
6. Adicione as variáveis (uma por linha):
   - `DATABASE_URL` = a mesma URL do Supabase que está no seu `.env` (postgresql://postgres:...@db....supabase.co:5432/postgres — use porta **6543** no Session pooler se tiver problema de IPv4)
   - `PORT` = `4100` (o Railway pode preencher sozinho; se já existir, não precisa mudar)
   - `ADMIN_SECRET` = uma chave secreta forte (ex.: senha longa ou UUID). Necessária para acessar o painel e criar projetos.
   - `BASE_URL` = URL pública da API (ex.: `https://track.ascensaodomentor.com`). Usada nos snippets do painel.
   - (Opcional) `META_PIXEL_ID`, `META_ACCESS_TOKEN`, `META_TEST_EVENT_CODE` se quiser Meta global (fallback quando o projeto não tem integração)
   - (Opcional) **Meta Ads (listar campanhas e gastos):** `META_ADS_APP_ID`, `META_ADS_APP_SECRET` (crie um app em developers.facebook.com com permissão `ads_read`; use a mesma `BASE_URL` como redirect). Rode no banco o script `sql/meta_ads.sql` para criar a tabela `meta_ads_connections`.
   - (Opcional) **Alerta global em compras:** `ALERT_WEBHOOK_URL` — URL chamada em toda compra (além do webhook por projeto). Útil para Slack, Zapier ou serviço de e-mail.
7. Em **Settings**, procure por **Public Networking** ou **Generate Domain** e ative. Se tiver domínio próprio (ex.: track.ascensaodomentor.com), configure em **Settings → Domains**.
8. Anote a URL da API (ex.: `https://track.ascensaodomentor.com`).

---

## 3. Usar a URL em produção

**Recomendado:** use o **painel** para criar projetos e copiar script + webhook:

- Acesse: `https://track.ascensaodomentor.com/painel?key=SEU_ADMIN_SECRET` (troque pela sua chave definida em `ADMIN_SECRET`).
- Crie um projeto (nome; opcional: Pixel ID e Access Token do Meta).
- Copie o **script para o cabeçalho** e a **URL do webhook Kiwify** exibidos no painel.

### No seu site (script do SDK)

Use o snippet exibido no painel ou, manualmente, a URL base da API (ex.: `https://track.ascensaodomentor.com`, sem barra no final):

```html
<script src="https://track.ascensaodomentor.com/sdk/browser-tracker.js"></script>
<script>
  var tracker = TrackingCore.createTracker({
    endpoint: 'https://track.ascensaodomentor.com/events',
    apiKey: 'pk_live_xxxxxxxxxxxxxxxx'
  });
  tracker.trackPageView();
  // tracker.trackPurchase({ order_id: '...', value: 99.9, currency: 'BRL' });
</script>
```

### Na Kiwify (webhook)

- URL do webhook: `https://track.ascensaodomentor.com/webhooks/kiwify?project_key=sk_live_xxxxxxxxxxxxxxxx`
- Use exatamente a **api_key_secret** do seu projeto (visível no painel ou no banco).

### API de consulta (estatísticas)

- `GET /api/stats?period=7d` — retorna eventos, compras e valor total do projeto no período. Requer header `X-API-Key` com a chave pública do projeto. Parâmetros: `period` (1d, 7d, 30d, all) ou `from` e `to` (datas ISO). Útil para integrações e BI.

---

## 4. Conferir

- Abra: `https://track.ascensaodomentor.com/health` → deve retornar `{"ok":true,...}`.
- Abra: `https://track.ascensaodomentor.com/painel?key=SEU_ADMIN_SECRET` → painel com projetos, script e webhook.
- Abra: `https://track.ascensaodomentor.com/sdk/browser-tracker.js` → deve mostrar o código do script.
- Depois de colocar o script no site e gerar um evento, confira no Supabase se apareceram linhas nas tabelas `raw_events` e `normalized_events`.

---

## Alternativa: Render

Se preferir o **Render** (render.com):

1. New → Web Service.
2. Conecte o repositório GitHub do `tracking-core`.
3. Build command: `npm install`
4. Start command: `npm start`
5. Em **Environment**, adicione `DATABASE_URL` (e as outras se quiser).
6. Deploy. O Render dá uma URL tipo `tracking-core.onrender.com`.

Use essa URL no lugar da do Railway nos passos 3 e 4 acima.
