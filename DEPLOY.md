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
   git remote add origin https://github.com/SEU_USUARIO/tracking-core.git
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

1. Acesse **https://railway.app** e entre com o GitHub.
2. Clique em **New Project**.
3. Escolha **Deploy from GitHub repo** e selecione o repositório `tracking-core`.
4. O Railway vai detectar que é Node e fazer o deploy. Se pedir **root directory**, deixe em branco ou `./`.
5. Clique no projeto e depois no **serviço** (o quadrado que apareceu). Vá em **Variables** (Variáveis).
6. Adicione as variáveis (uma por linha):
   - `DATABASE_URL` = a mesma URL do Supabase que está no seu `.env` (postgresql://postgres:...@db....supabase.co:5432/postgres)
   - `PORT` = `4100` (o Railway pode preencher sozinho; se já existir, não precisa mudar)
   - (Opcional) `META_PIXEL_ID`, `META_ACCESS_TOKEN`, `META_TEST_EVENT_CODE` se quiser Meta global
7. Em **Settings**, procure por **Public Networking** ou **Generate Domain** e ative. O Railway vai mostrar uma URL tipo `tracking-core-production.up.railway.app`.
8. Anote essa URL (ex.: `https://tracking-core-production.up.railway.app`). Essa é a **URL da sua API em produção**.

---

## 3. Usar a URL em produção

### No seu site (script do SDK)

Troque `http://localhost:4100` pela URL do Railway (sem barra no final):

```html
<script src="https://SUA-URL-RAILWAY.app/sdk/browser-tracker.js"></script>
<script>
  var tracker = TrackingCore.createTracker({
    endpoint: 'https://SUA-URL-RAILWAY.app/events',
    apiKey: 'pk_live_xxxxxxxxxxxxxxxx'
  });
  tracker.trackPageView();
  // tracker.trackPurchase({ order_id: '...', value: 99.9, currency: 'BRL' });
</script>
```

### Na Kiwify (webhook)

- URL do webhook: `https://SUA-URL-RAILWAY.app/webhooks/kiwify?project_key=sk_live_xxxxxxxxxxxxxxxx`
- Use exatamente a **api_key_secret** do seu projeto (a mesma que está no banco).

---

## 4. Conferir

- Abra no navegador: `https://SUA-URL-RAILWAY.app/health` → deve retornar `{"ok":true,...}`.
- Abra: `https://SUA-URL-RAILWAY.app/sdk/browser-tracker.js` → deve mostrar o código do script.
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
