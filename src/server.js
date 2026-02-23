import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import pkg from 'pg';
import axios from 'axios';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

dotenv.config();

const { Pool } = pkg;

// Configuração básica de ambiente
const PORT = process.env.PORT || 4100;
const DATABASE_URL = process.env.DATABASE_URL || null;

// Configurações Meta (opcionais, mas necessárias para envio real)
const META_PIXEL_ID = process.env.META_PIXEL_ID || null;
const META_ACCESS_TOKEN = process.env.META_ACCESS_TOKEN || null;
const META_TEST_EVENT_CODE = process.env.META_TEST_EVENT_CODE || null;

const hasMetaConfig = Boolean(META_PIXEL_ID && META_ACCESS_TOKEN);

// Painel admin: chave para acessar /painel e criar projetos
const ADMIN_SECRET = process.env.ADMIN_SECRET || null;
const BASE_URL = process.env.BASE_URL || null; // ex: https://track.ascensaodomentor.com

// Meta Marketing API (OAuth para listar campanhas e gastos)
const META_ADS_APP_ID = process.env.META_ADS_APP_ID || null;
const META_ADS_APP_SECRET = process.env.META_ADS_APP_SECRET || null;
const hasMetaAdsOAuthConfig = Boolean(META_ADS_APP_ID && META_ADS_APP_SECRET && BASE_URL);

// Rate limit (por minuto, por chave)
const RATE_LIMIT_EVENTS = parseInt(process.env.RATE_LIMIT_EVENTS_PER_MIN, 10) || 120;
const RATE_LIMIT_WEBHOOK = parseInt(process.env.RATE_LIMIT_WEBHOOK_PER_MIN, 10) || 60;
const rateLimitStore = new Map(); // key -> { count, resetAt }

function getClientIp(req) {
  return req.ip || req.get('x-forwarded-for')?.split(',')[0]?.trim() || req.socket?.remoteAddress || '';
}

function rateLimit(maxPerMinute, keyFn) {
  return (req, res, next) => {
    const key = keyFn(req);
    if (!key) return next();
    const now = Date.now();
    const windowMs = 60 * 1000;
    let entry = rateLimitStore.get(key);
    if (!entry || now >= entry.resetAt) {
      entry = { count: 0, resetAt: now + windowMs };
      rateLimitStore.set(key, entry);
    }
    entry.count++;
    if (entry.count > maxPerMinute) {
      return res.status(429).json({ error: 'Muitas requisições. Tente novamente em alguns minutos.' });
    }
    next();
  };
}

// Pool de conexão com Postgres (opcional, mas recomendado)
let pool = null;
if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL
  });
} else {
  console.warn(
    '[tracking-core] DATABASE_URL não definido. Eventos não serão persistidos em banco (apenas logados em memória).'
  );
}

const app = express();

// Evita crash por erros não tratados em rotas async (Express 4 não os captura)
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/sdk', express.static(path.join(__dirname, '../sdk')));
app.use('/public', express.static(path.join(__dirname, '../public')));

// Middleware: resolve project_id via X-API-Key (quando há banco)
app.use(async (req, res, next) => {
  const apiKey = req.header('X-API-Key');
  if (!apiKey) {
    req.projectId = null;
    return next();
  }
  if (!pool) {
    req.projectId = null;
    return next();
  }
  try {
    const r = await pool.query(
      'SELECT id FROM projects WHERE api_key_public = $1 AND status = $2 LIMIT 1',
      [apiKey, 'active']
    );
    req.projectId = r.rows[0]?.id ?? null;
  } catch (e) {
    req.projectId = null;
  }
  next();
});

// Utilitários
function sha256Lower(text) {
  return crypto.createHash('sha256').update(text).digest('hex').toLowerCase();
}

function generateApiKeys() {
  const suffix = crypto.randomBytes(12).toString('hex');
  return {
    public: `pk_live_${suffix}`,
    secret: `sk_live_${suffix}`
  };
}

function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function csvEscape(s) {
  if (s == null) return '';
  const str = String(s);
  if (/[",\r\n]/.test(str)) return '"' + str.replace(/"/g, '""') + '"';
  return str;
}

/** Layout compartilhado do painel: sidebar (Dashboard, Pixel, Projetos) + área principal */
function painelLayout(opts) {
  const { activeNav = 'dashboard', title = 'Painel', headerLogo = '', headerRight = '', content = '', adminKey = '', extraScripts = '' } = opts;
  const q = (adminKey ? '?key=' + encodeURIComponent(adminKey) : '');
  const href = (path) => path + (path.indexOf('?') !== -1 ? (adminKey ? '&key=' + encodeURIComponent(adminKey) : '') : q);
  const link = (path, label, nav) =>
    `<a href="${href(path)}" class="sidebar-link${nav === activeNav ? ' active' : ''}">${escapeHtml(label)}</a>`;
  const sidebarHtml = `
    <div class="sidebar-logo">Tracking Core</div>
    <nav class="sidebar-nav">
      ${link('/painel', 'Dashboard', 'dashboard')}
      ${link('/painel/pixel', 'Pixel', 'pixel')}
      ${link('/painel/projetos', 'Projetos', 'projetos')}
      ${link('/painel/meta-ads', 'Meta Ads', 'meta_ads')}
    </nav>
    <a href="/logout" class="sidebar-link sidebar-logout">Sair</a>`;
  const headerLeft = headerLogo ? `<span class="dashboard-header-logo">${escapeHtml(headerLogo)}</span>` : '';
  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} – Tracking Core</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Exo+2:wght@400;500;600;700&family=Orbitron:wght@500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/public/painel.css">
</head>
<body>
  <div class="dashboard-wrap" id="dashboardWrap">
    <div class="sidebar-overlay" id="sidebarOverlay" aria-hidden="true"></div>
    <aside class="dashboard-sidebar">${sidebarHtml}</aside>
    <main class="dashboard-main">
      <header class="dashboard-header">
        <button type="button" class="btn-hamburger" id="btnHamburger" aria-label="Abrir menu">≡</button>
        <div class="dashboard-header-left">${headerLeft}<h1 class="dashboard-title">${escapeHtml(title)}</h1></div>
        <div class="dashboard-header-right">${headerRight}</div>
      </header>
      <div class="dashboard-content">${content}</div>
    </main>
    <nav class="scroll-jump" aria-label="Ir para posição do scroll">
      <button type="button" class="scroll-jump__btn" data-pct="25" title="Scroll 25%">25%</button>
      <button type="button" class="scroll-jump__btn" data-pct="50" title="Scroll 50%">50%</button>
      <button type="button" class="scroll-jump__btn" data-pct="75" title="Scroll 75%">75%</button>
      <button type="button" class="scroll-jump__btn" data-pct="100" title="Scroll 100%">100%</button>
    </nav>
  </div>
  <script>
    (function() {
      var wrap = document.getElementById('dashboardWrap');
      var overlay = document.getElementById('sidebarOverlay');
      var hamburger = document.getElementById('btnHamburger');
      if (wrap && overlay && hamburger) {
        hamburger.addEventListener('click', function() { wrap.classList.toggle('sidebar-open'); });
        overlay.addEventListener('click', function() { wrap.classList.remove('sidebar-open'); });
        wrap.querySelectorAll('.sidebar-link').forEach(function(l) { l.addEventListener('click', function() { wrap.classList.remove('sidebar-open'); }); });
      }
      document.querySelectorAll('.scroll-jump__btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var pct = parseInt(btn.getAttribute('data-pct'), 10) || 50;
          var maxScroll = document.documentElement.scrollHeight - window.innerHeight;
          var target = Math.round((maxScroll * pct) / 100);
          window.scrollTo({ top: target, behavior: 'smooth' });
        });
      });
    })();
  </script>
  ${extraScripts ? extraScripts + '\n  ' : ''}</body>
</html>`;
}

// Catálogo de conversões com tooltip (?) para cada uma
const CONVERSION_CATALOG = [
  { key: 'PageView', label: 'PageView (página)', tooltip: 'Registra visualização de página. Use no &lt;head&gt; ou ao carregar o site para rastrear todas as visitas.' },
  { key: 'ViewContent', label: 'ViewContent (conteúdo)', tooltip: 'Registra visualização de conteúdo/produto. Use em páginas de oferta ou produto.' },
  { key: 'AddToCart', label: 'AddToCart (carrinho)', tooltip: 'Dispara quando o usuário adiciona ao carrinho. Cole no botão "Adicionar ao carrinho".' },
  { key: 'InitiateCheckout', label: 'InitiateCheckout (checkout)', tooltip: 'Dispara ao iniciar o checkout. Cole no botão "Comprar" ou na página de checkout.' },
  { key: 'Purchase', label: 'Purchase (compra)', tooltip: 'Registra compra concluída. Use na página de obrigado (thank you) com order_id e valor.' },
  { key: 'Lead', label: 'Lead', tooltip: 'Registra lead (cadastro, formulário). Use ao enviar formulário de captura.' },
  { key: 'Contact', label: 'Contact', tooltip: 'Registra contato (formulário, chat). Use em botões ou envio de contato.' },
  { key: 'Scroll', label: 'Scroll (25%, 50%, 75%, 100%)', tooltip: 'Envia um evento quando a pessoa rola 25%, 50%, 75% ou 100% da página. Use para ver até onde os visitantes vão (engajamento).' }
];

function conversionLabelWithTooltip(c) {
  const tipPlain = (c.tooltip || '').replace(/<[^>]+>/g, ' ').replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/\s+/g, ' ').trim();
  const tipAttr = (tipPlain || 'Ajuda').replace(/"/g, '&quot;');
  return `${escapeHtml(c.label)} <span class="conversion-tooltip" data-tooltip="${tipAttr}" title="${escapeHtml(tipPlain)}" aria-label="Ajuda">?</span>`;
}

function buildConversionSnippet(conversionKey, baseUrl, apiKey) {
  const apiKeyEsc = (apiKey || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  const base = `<script src="${baseUrl}/sdk/browser-tracker.js"></script>
<script>
  (function(){
    var t = TrackingCore.createTracker({ endpoint: '${baseUrl}/events', apiKey: '${apiKeyEsc}' });`;
  const lines = {
    PageView: "    t.trackPageView();",
    ViewContent: "    t.trackViewContent({});",
    AddToCart: "    t.trackAddToCart({});",
    InitiateCheckout: "    t.trackInitiateCheckout({});",
    Purchase: "    t.trackPurchase({ order_id: 'PEDIDO', value: 0, currency: 'BRL' });",
    Lead: "    t.trackLead({});",
    Contact: "    t.trackContact({});",
    Scroll: "    t.trackScrollDepth({ percentMarks: [25, 50, 75, 100] });"
  };
  const line = lines[conversionKey];
  if (!line) return base + "\n  window._trackingCore = t;\n  })();\n</script>";
  return base + "\n" + line + "\n  window._trackingCore = t;\n  })();\n</script>";
}

// Uma linha só (para colar em botão/elemento quando o script principal já está no site)
function buildInlineSnippet(conversionKey) {
  const map = {
    PageView: 'window._trackingCore && window._trackingCore.trackPageView();',
    ViewContent: 'window._trackingCore && window._trackingCore.trackViewContent({});',
    AddToCart: 'window._trackingCore && window._trackingCore.trackAddToCart({});',
    InitiateCheckout: 'window._trackingCore && window._trackingCore.trackInitiateCheckout({});',
    Purchase: 'window._trackingCore && window._trackingCore.trackPurchase({ order_id: \'PEDIDO\', value: 0, currency: \'BRL\' });',
    Lead: 'window._trackingCore && window._trackingCore.trackLead({});',
    Contact: 'window._trackingCore && window._trackingCore.trackContact({});',
    Scroll: 'window._trackingCore && window._trackingCore.trackScrollDepth({ percentMarks: [25, 50, 75, 100] });'
  };
  return map[conversionKey] || '';
}

function buildFullScript(conversionKeys, baseUrl, apiKey) {
  const apiKeyEsc = (apiKey || '').replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  const lines = [];
  (conversionKeys || ['PageView']).forEach((key) => {
    const map = {
      PageView: "  t.trackPageView();",
      ViewContent: "  t.trackViewContent({});",
      AddToCart: "  t.trackAddToCart({});",
      InitiateCheckout: "  t.trackInitiateCheckout({});",
      Purchase: "  t.trackPurchase({ order_id: 'PEDIDO', value: 0, currency: 'BRL' });",
      Lead: "  t.trackLead({});",
      Contact: "  t.trackContact({});",
      Scroll: "  t.trackScrollDepth({ percentMarks: [25, 50, 75, 100] });"
    };
    if (map[key]) lines.push(map[key]);
  });
  return `<script src="${baseUrl}/sdk/browser-tracker.js"></script>
<script>
(function(){
  var t = TrackingCore.createTracker({ endpoint: '${baseUrl}/events', apiKey: '${apiKeyEsc}' });
  window._trackingCore = t;
${lines.join('\n')}
})();
</script>`;
}

// Cookie de sessão do painel (assinado, sem banco)
const ADMIN_COOKIE_NAME = 'tracking_admin';
const ADMIN_SESSION_MAX_AGE = 24 * 60 * 60; // 24h em segundos

function getCookie(req, name) {
  const raw = req.headers.cookie;
  if (!raw) return null;
  const match = raw.match(new RegExp('(?:^|;)\\s*' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)'));
  return match ? decodeURIComponent(match[1].trim()) : null;
}

function createAdminSessionCookie() {
  const payload = { exp: Math.floor(Date.now() / 1000) + ADMIN_SESSION_MAX_AGE };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sign = crypto.createHmac('sha256', ADMIN_SECRET).update(payloadB64).digest('base64url');
  return payloadB64 + '.' + sign;
}

function verifyAdminCookie(req) {
  const raw = getCookie(req, ADMIN_COOKIE_NAME);
  if (!raw) return false;
  const parts = raw.split('.');
  if (parts.length !== 2) return false;
  try {
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    const sign = crypto.createHmac('sha256', ADMIN_SECRET).update(parts[0]).digest('base64url');
    if (sign !== parts[1] || payload.exp < Math.floor(Date.now() / 1000)) return false;
    return true;
  } catch {
    return false;
  }
}

function buildNormalizedEvent(ev, projectId, source) {
  const now = new Date().toISOString();
  const eventId = ev.event_id || crypto.randomUUID();
  const orderId = ev.properties?.order_id || ev.properties?.orderId || null;
  const value = ev.properties?.value ?? null;
  const currency = ev.properties?.currency || 'BRL';

  const userHashes = {};
  if (ev.user?.email) {
    userHashes.em = sha256Lower(ev.user.email.trim().toLowerCase());
  }

  const context = {
    url: ev.context?.url || null,
    referrer: ev.context?.referrer || null,
    utm_source: ev.context?.utm_source || null,
    utm_medium: ev.context?.utm_medium || null,
    utm_campaign: ev.context?.utm_campaign || null,
    utm_content: ev.context?.utm_content || null,
    utm_term: ev.context?.utm_term || null
  };

  return {
    id: crypto.randomUUID(),
    project_id: projectId,
    event_name: ev.event_name,
    event_id: eventId,
    order_id: orderId,
    value,
    currency,
    user_hashes: userHashes,
    context,
    source,
    source_priority: source === 'gateway' ? 2 : 1,
    status: 'pending_meta',
    created_at: now
  };
}

async function getMetaConfig(projectId) {
  if (pool && projectId) {
    const r = await pool.query(
      'SELECT pixel_id, access_token, test_event_code FROM integrations_meta WHERE project_id = $1 AND active = true LIMIT 1',
      [projectId]
    );
    if (r.rows[0]) {
      return {
        pixelId: r.rows[0].pixel_id,
        accessToken: r.rows[0].access_token,
        testEventCode: r.rows[0].test_event_code || null
      };
    }
  }
  if (META_PIXEL_ID && META_ACCESS_TOKEN) {
    return {
      pixelId: META_PIXEL_ID,
      accessToken: META_ACCESS_TOKEN,
      testEventCode: META_TEST_EVENT_CODE || null
    };
  }
  return null;
}

// Webhook de saída: notifica URL externa em compras (fire-and-forget)
async function notifyOutgoingWebhook(projectId, normalizedEvent) {
  if (normalizedEvent.event_name !== 'Purchase' || !pool) return;
  let url;
  try {
    const r = await pool.query(
      'SELECT webhook_out_url FROM projects WHERE id = $1 AND webhook_out_url IS NOT NULL AND webhook_out_url != \'\' LIMIT 1',
      [projectId]
    );
    url = r.rows[0]?.webhook_out_url;
  } catch (e) {
    return;
  }
  if (!url) return;
  const payload = {
    event_name: normalizedEvent.event_name,
    event_id: normalizedEvent.event_id,
    order_id: normalizedEvent.order_id,
    value: normalizedEvent.value,
    currency: normalizedEvent.currency || 'BRL',
    source: normalizedEvent.source,
    created_at: normalizedEvent.created_at
  };
  axios.post(url, payload, { timeout: 8000, validateStatus: () => true }).catch((err) => {
    console.warn('[tracking-core] Webhook de saída falhou:', err.message);
  });
}

async function sendToMeta(normalizedEvent, req, projectId) {
  const meta = await getMetaConfig(projectId);
  if (!meta) {
    return { skipped: true, reason: 'meta_not_configured' };
  }

  const url = `https://graph.facebook.com/v18.0/${meta.pixelId}/events`;

  const clientIp =
    (req && req.headers && req.headers['x-forwarded-for'] &&
      req.headers['x-forwarded-for'].toString().split(',')[0].trim()) ||
    (req && req.socket && req.socket.remoteAddress) ||
    (req && req.ip) ||
    '';

  const clientUserAgent = (req && req.headers && req.headers['user-agent']) || '';

  const userData = {
    client_ip_address: clientIp,
    client_user_agent: clientUserAgent
  };

  if (normalizedEvent.user_hashes?.em) {
    userData.em = [normalizedEvent.user_hashes.em];
  }

  const payload = {
    data: [
      {
        event_name: normalizedEvent.event_name,
        event_time: Math.floor(Date.now() / 1000),
        event_id: normalizedEvent.event_id,
        event_source_url: normalizedEvent.context?.url || undefined,
        action_source: 'website',
        user_data: userData,
        custom_data: {
          value: normalizedEvent.value,
          currency: normalizedEvent.currency || 'BRL'
        }
      }
    ],
    access_token: meta.accessToken
  };

  if (meta.testEventCode) {
    payload.test_event_code = meta.testEventCode;
  }

  try {
    const res = await axios.post(url, payload);
    return { skipped: false, ok: true, meta: res.data };
  } catch (err) {
    console.error(
      '[tracking-core] Erro ao enviar evento para Meta:',
      err.response?.data || err.message
    );
    return {
      skipped: false,
      ok: false,
      error: err.response?.data || { message: err.message }
    };
  }
}

// Health: checa API, banco e (opcional) Meta
app.get('/health', async (req, res) => {
  const out = { ok: true, time: new Date().toISOString(), db: null, meta: null };
  if (pool) {
    try {
      await pool.query('SELECT 1');
      out.db = 'connected';
    } catch (e) {
      out.db = 'error';
      out.ok = false;
      out.db_error = e.message;
    }
  } else {
    out.db = 'not_configured';
  }
  out.meta = hasMetaConfig ? 'configured' : 'not_configured';
  const status = out.ok ? 200 : 503;
  res.status(status).json(out);
});

// Rota /events (equivalente evoluída do MVP)
app.post(
  '/events',
  rateLimit(RATE_LIMIT_EVENTS, (req) => `ev:${req.projectId || getClientIp(req)}`),
  async (req, res) => {
  try {
    const body = req.body;
    const events = Array.isArray(body) ? body : [body];

    for (const ev of events) {
      if (!ev.event_name) {
        return res.status(400).json({ error: 'event_name é obrigatório' });
      }
    }

    const projectId = req.projectId;
    const receivedAt = new Date().toISOString();

    if (pool && !projectId) {
      return res.status(401).json({ error: 'X-API-Key inválida ou ausente' });
    }

    if (!pool) {
      console.log('[tracking-core] Evento recebido (modo sem DB):', {
        projectId,
        events
      });
      return res.json({ ok: true, mode: 'no_db' });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      for (const ev of events) {
        const rawId = crypto.randomUUID();

        await client.query(
          `
          INSERT INTO raw_events (id, project_id, source, payload, received_at, status)
          VALUES ($1, $2, $3, $4, $5, $6)
        `,
          [
            rawId,
            projectId,
            ev.source || 'sdk',
            JSON.stringify(ev),
            receivedAt,
            'pending'
          ]
        );

        const normalized = buildNormalizedEvent(ev, projectId, ev.source || 'sdk');

        let normalizedInserted = false;
        try {
          await client.query(
            `
            INSERT INTO normalized_events (
              id, project_id, event_name, event_id, order_id, value, currency,
              user_hashes, context, source, source_priority, status, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
          `,
            [
              normalized.id,
              normalized.project_id,
              normalized.event_name,
              normalized.event_id,
              normalized.order_id,
              normalized.value,
              normalized.currency,
              JSON.stringify(normalized.user_hashes),
              JSON.stringify(normalized.context),
              normalized.source,
              normalized.source_priority,
              normalized.status,
              normalized.created_at
            ]
          );
          normalizedInserted = true;
        } catch (insertErr) {
          if (insertErr.code === '23505') {
            // Já existe (ex.: webhook + SDK mesmo order_id) — só marca raw como processado
          } else {
            throw insertErr;
          }
        }

        if (normalizedInserted) {
          const metaResult = await sendToMeta(normalized, req, projectId);

          if (!metaResult.skipped) {
            const deliveryId = crypto.randomUUID();
            await client.query(
              `
              INSERT INTO deliveries_meta (
                id, normalized_event_id, status, attempts, last_error, meta_response, sent_at
              )
              VALUES ($1, $2, $3, $4, $5, $6, $7)
            `,
              [
                deliveryId,
                normalized.id,
                metaResult.ok ? 'sent' : 'failed',
                1,
                metaResult.ok ? null : JSON.stringify(metaResult.error),
                metaResult.ok ? JSON.stringify(metaResult.meta) : null,
                metaResult.ok ? new Date().toISOString() : null
              ]
            );

            await client.query(
              `UPDATE normalized_events SET status = $2 WHERE id = $1`,
              [normalized.id, metaResult.ok ? 'sent' : 'failed']
            );
          }
          if (normalized.event_name === 'Purchase') notifyOutgoingWebhook(projectId, normalized);
        }

        await client.query(
          `UPDATE raw_events SET status = $2 WHERE id = $1`,
          [rawId, 'processed']
        );
      }

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('[tracking-core] Erro ao processar /events:', err.message);
      return res.status(500).json({ error: 'Erro ao processar eventos' });
    } finally {
      client.release();
    }

    return res.json({ ok: true, mode: 'db_with_meta_pipeline' });
  } catch (err) {
    console.error('[tracking-core] Erro em /events:', err.message);
    return res.status(500).json({ error: 'Erro ao processar eventos' });
  }
  }
);

// Mapeia payload genérico de gateway (Kiwify e similares) para evento interno
function mapGatewayPayloadToEvent(body, gateway) {
  const orderId =
    body.order_id ||
    body.id ||
    body.transaction_id ||
    body.reference ||
    (body.order && body.order.id) ||
    null;
  const valueRaw =
    body.value ??
    body.amount ??
    body.total ??
    (body.order && body.order.amount) ??
    (body.commission && body.commission.value);
  const value =
    typeof valueRaw === 'number'
      ? valueRaw
      : typeof valueRaw === 'string'
        ? parseFloat(valueRaw.replace(/,/, '.'))
        : null;
  const email =
    body.email ||
    body.customer_email ||
    (body.customer && body.customer.email) ||
    (body.buyer && body.buyer.email) ||
    null;

  return {
    event_name: 'Purchase',
    event_id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    user: { email: email || undefined },
    context: {},
    properties: {
      order_id: orderId,
      value: value != null ? value : undefined,
      currency: body.currency || 'BRL'
    },
    source: gateway
  };
}

// --- Painel admin (login por senha ou ?key= / cookie de sessão) ---
function checkAdmin(req, res) {
  if (!ADMIN_SECRET) {
    return res.status(503).json({ error: 'Painel desativado: ADMIN_SECRET não configurado' });
  }
  const key = req.query.key || req.header('X-Admin-Key') || '';
  if (key === ADMIN_SECRET) return null;
  if (verifyAdminCookie(req)) return null;
  return res.status(401).json({ error: 'Não autorizado' });
}

function isAdminAuthorized(req) {
  if (!ADMIN_SECRET) return false;
  if ((req.query.key || req.header('X-Admin-Key') || '') === ADMIN_SECRET) return true;
  return verifyAdminCookie(req);
}

function setAdminCookie(res) {
  const val = createAdminSessionCookie();
  let cookie = `${ADMIN_COOKIE_NAME}=${val}; Path=/; Max-Age=${ADMIN_SESSION_MAX_AGE}; HttpOnly; SameSite=Lax`;
  if (process.env.NODE_ENV === 'production') cookie += '; Secure';
  res.setHeader('Set-Cookie', cookie);
}

function clearAdminCookie(res) {
  res.setHeader('Set-Cookie', `${ADMIN_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`);
}

const loginPageHtml = (errorMsg = '') => `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login – Painel Tracking Core</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Exo+2:wght@400;500;600;700&family=Orbitron:wght@500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/public/painel.css">
</head>
<body>
  <div class="login-page">
    <div class="login-card">
      <h1>Tracking Core</h1>
      <p class="subtitle">Entre com a senha de administrador.</p>
      <form method="post" action="/login">
        <span class="label">Senha</span>
        <input type="password" id="password" name="password" required autofocus placeholder="Senha">
        ${errorMsg ? '<p class="error">' + escapeHtml(errorMsg) + '</p>' : ''}
        <button type="submit" class="btn btn-primary">Entrar</button>
      </form>
    </div>
  </div>
</body>
</html>`;

app.get('/login', (req, res) => {
  if (!ADMIN_SECRET) return res.status(503).send('Painel desativado. Configure ADMIN_SECRET.');
  if (isAdminAuthorized(req)) return res.redirect(302, '/painel');
  res.type('html').send(loginPageHtml());
});

app.post('/login', (req, res) => {
  if (!ADMIN_SECRET) return res.status(503).send('Painel desativado.');
  const password = (req.body?.password || '').trim();
  if (password !== ADMIN_SECRET) {
    return res.type('html').status(401).send(loginPageHtml('Senha incorreta.'));
  }
  setAdminCookie(res);
  res.redirect(302, '/painel');
});

app.get('/logout', (req, res) => {
  clearAdminCookie(res);
  res.redirect(302, '/login');
});

async function getOrCreateDefaultTenant(client) {
  const r = await client.query("SELECT id FROM tenants WHERE status = 'active' LIMIT 1");
  if (r.rows[0]) return r.rows[0].id;
  const ins = await client.query(
    "INSERT INTO tenants (name, status) VALUES ('Default', 'active') RETURNING id"
  );
  return ins.rows[0].id;
}

app.get('/painel', asyncHandler(async (req, res) => {
  if (!ADMIN_SECRET) return res.status(503).send('Painel desativado. Configure ADMIN_SECRET.');
  if (!isAdminAuthorized(req)) return res.redirect(302, '/login');
  if (!pool) {
    return res.status(503).send('Banco não configurado. Configure DATABASE_URL.');
  }
  // Se entrou com ?key=, grava cookie para não precisar da key na próxima vez
  if (req.query.key === ADMIN_SECRET) setAdminCookie(res);
  const baseUrl = BASE_URL || `${req.protocol}://${req.get('host')}`;
  const adminKey = req.query.key || '';
  const period = req.query.period || 'all'; // all | 1d | 7d | 30d
  let dateFrom = null;
  if (period === '1d') dateFrom = new Date(Date.now() - 24 * 60 * 60 * 1000);
  else if (period === '7d') dateFrom = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  else if (period === '30d') dateFrom = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  let projects = [];
  try {
    const r = await pool.query(
      `SELECT p.id, p.name, p.api_key_public, p.api_key_secret, p.webhook_out_url,
              EXISTS(SELECT 1 FROM integrations_meta m WHERE m.project_id = p.id AND m.active) AS has_meta
       FROM projects p
       WHERE p.status = 'active'
       ORDER BY p.created_at DESC`
    );
    projects = r.rows.map((row) => ({
      id: row.id,
      name: row.name,
      api_key_public: row.api_key_public,
      api_key_secret: row.api_key_secret,
      webhook_out_url: row.webhook_out_url || '',
      has_meta: row.has_meta,
      script_snippet: `<script src="${baseUrl}/sdk/browser-tracker.js"></script>
<script>
  (function(){
    var t = TrackingCore.createTracker({
      endpoint: '${baseUrl}/events',
      apiKey: '${row.api_key_public}'
    });
    t.trackPageView();
  })();
</script>`,
      webhook_url: `${baseUrl}/webhooks/kiwify?project_key=${encodeURIComponent(row.api_key_secret)}`
    }));
  } catch (e) {
    console.error('[tracking-core] Erro ao listar projetos no painel:', e.message);
    return res.status(500).send('Erro ao carregar projetos.');
  }

  let inactiveProjects = [];
  try {
    const rInactive = await pool.query(
      `SELECT id, name FROM projects WHERE status = 'inactive' ORDER BY created_at DESC`
    );
    inactiveProjects = rInactive.rows;
  } catch (e) {
    // ignora; lista de inativos é opcional
  }

  let statsByProject = {};
  try {
    const dateCondition = dateFrom ? ' AND created_at >= $1' : '';
    const params = dateFrom ? [dateFrom.toISOString()] : [];
    const rStats = await pool.query(
      `SELECT project_id,
              COUNT(*) AS total_events,
              COUNT(*) FILTER (WHERE event_name = 'Purchase') AS purchases,
              COALESCE(SUM(value) FILTER (WHERE event_name = 'Purchase'), 0) AS total_value
       FROM normalized_events
       WHERE 1=1${dateCondition}
       GROUP BY project_id`,
      params
    );
    rStats.rows.forEach((row) => {
      statsByProject[row.project_id] = {
        total_events: parseInt(row.total_events, 10),
        purchases: parseInt(row.purchases, 10),
        total_value: parseFloat(row.total_value) || 0
      };
    });
  } catch (e) {
    // ignora
  }

  let costByUtm = {};
  try {
    const rCost = await pool.query('SELECT utm_source, utm_medium, utm_campaign, cost FROM campaign_costs');
    rCost.rows.forEach((row) => {
      const key = [row.utm_source, row.utm_medium, row.utm_campaign].join('\0');
      costByUtm[key] = parseFloat(row.cost) || 0;
    });
  } catch (e) {
    // ignora (tabela pode não existir)
  }

  let utmRows = [];
  try {
    const dateCondUtm = dateFrom ? ' AND created_at >= $1' : '';
    const utmParams = dateFrom ? [dateFrom.toISOString()] : [];
    const rUtm = await pool.query(
      `SELECT
        COALESCE(context->>'utm_source', '—') AS utm_source,
        COALESCE(context->>'utm_medium', '—') AS utm_medium,
        COALESCE(context->>'utm_campaign', '—') AS utm_campaign,
        COUNT(*) AS purchases,
        COALESCE(SUM(value), 0) AS total_value
       FROM normalized_events
       WHERE event_name = 'Purchase'${dateCondUtm}
       GROUP BY context->>'utm_source', context->>'utm_medium', context->>'utm_campaign'
       ORDER BY total_value DESC
       LIMIT 50`,
      utmParams
    );
    utmRows = rUtm.rows.map((row) => {
      const purchases = parseInt(row.purchases, 10) || 0;
      const v = parseFloat(row.total_value) || 0;
      const valueStr = v > 0 ? 'R$ ' + Number(v).toFixed(2).replace('.', ',') : '—';
      const key = [row.utm_source, row.utm_medium, row.utm_campaign].join('\0');
      const cost = costByUtm[key] ?? 0;
      const costStr = cost > 0 ? 'R$ ' + Number(cost).toFixed(2).replace('.', ',') : '';
      const cpaStr = cost > 0 && purchases > 0 ? 'R$ ' + Number(cost / purchases).toFixed(2).replace('.', ',') : '—';
      const roasStr = cost > 0 && v > 0 ? Number(v / cost).toFixed(2).replace('.', ',') : '—';
      const us = escapeHtml(row.utm_source);
      const um = escapeHtml(row.utm_medium);
      const uc = escapeHtml(row.utm_campaign);
      return `<tr class="utm-cost-row" data-us="${us}" data-um="${um}" data-uc="${uc}">
        <td>${us}</td><td>${um}</td><td>${uc}</td><td>${purchases}</td><td>${valueStr}</td>
        <td><input type="number" step="0.01" min="0" class="input-cost" value="${cost > 0 ? cost : ''}" placeholder="0"></td>
        <td class="cpa-cell">${cpaStr}</td><td class="roas-cell">${roasStr}</td>
        <td><button type="button" class="btn btn-sm btn-save-cost">Salvar</button></td>
      </tr>`;
    });
  } catch (e) {
    // ignora
  }
  const utmRowsHtml = utmRows.join('');

  // Aba Campanhas: uma linha por UTM com colunas Campanha, Vendas, Faturamento, Custo, CPA, ROAS
  let campaignRowsForTab = '';
  try {
    const rUtm2 = await pool.query(
      `SELECT
        COALESCE(context->>'utm_source', '—') AS utm_source,
        COALESCE(context->>'utm_medium', '—') AS utm_medium,
        COALESCE(context->>'utm_campaign', '—') AS utm_campaign,
        COUNT(*) AS purchases,
        COALESCE(SUM(value), 0) AS total_value
       FROM normalized_events
       WHERE event_name = 'Purchase'${dateCondUtm}
       GROUP BY context->>'utm_source', context->>'utm_medium', context->>'utm_campaign'
       ORDER BY total_value DESC
       LIMIT 50`,
      utmParams
    );
    campaignRowsForTab = rUtm2.rows.map((row) => {
      const purchases = parseInt(row.purchases, 10) || 0;
      const v = parseFloat(row.total_value) || 0;
      const valueStr = v > 0 ? 'R$ ' + Number(v).toFixed(2).replace('.', ',') : '—';
      const key = [row.utm_source, row.utm_medium, row.utm_campaign].join('\0');
      const cost = costByUtm[key] ?? 0;
      const costStr = cost > 0 ? Number(cost).toFixed(2) : '';
      const cpaStr = cost > 0 && purchases > 0 ? 'R$ ' + Number(cost / purchases).toFixed(2).replace('.', ',') : '—';
      const roasStr = cost > 0 && v > 0 ? Number(v / cost).toFixed(2).replace('.', ',') : '—';
      const us = escapeHtml(row.utm_source);
      const um = escapeHtml(row.utm_medium);
      const uc = escapeHtml(row.utm_campaign);
      const campaignLabel = uc !== '—' ? `[${uc}] – ${row.utm_source}/${row.utm_medium}` : `${row.utm_source} / ${row.utm_medium}`;
      return `<tr class="utm-cost-row" data-us="${us}" data-um="${um}" data-uc="${uc}">
        <td><span class="campaign-name">${escapeHtml(campaignLabel)}</span></td>
        <td>${purchases}</td>
        <td>${valueStr}</td>
        <td><input type="number" step="0.01" min="0" class="input-cost" value="${cost > 0 ? cost : ''}" placeholder="0"></td>
        <td class="cpa-cell">${cpaStr}</td>
        <td class="roas-cell">${roasStr}</td>
        <td><button type="button" class="btn btn-sm btn-save-cost">Salvar</button></td>
      </tr>`;
    }).join('');
  } catch (e) {
    // ignora
  }
  const campaignPanelHtml = `<div class="dashboard-tabs-panel" id="panel-campanhas" aria-hidden="true" style="display:none">
    <div class="dashboard-table-wrap">
    <table class="dashboard-table dashboard-table-campaigns">
      <thead><tr><th>Campanha</th><th>Vendas</th><th>Faturamento</th><th>Custo (R$)</th><th>CPA</th><th>ROAS</th><th></th></tr></thead>
      <tbody>${campaignRowsForTab || '<tr><td colspan="7" class="events-empty">Nenhuma campanha (UTM) com compras no período.</td></tr>'}</tbody>
    </table>
    </div>
    <p class="metrics-legend">Gastos por campanha são informados manualmente. Para ver gastos automáticos da Meta, é necessária integração com a Meta Marketing API.</p>
  </div>`;

  let untrackedSalesCount = 0;
  try {
    const dateCondUntracked = dateFrom ? ' AND created_at >= $1' : '';
    const untrackedParams = dateFrom ? [dateFrom.toISOString()] : [];
    const rUntracked = await pool.query(
      `SELECT COUNT(*) AS cnt
       FROM normalized_events
       WHERE event_name = 'Purchase'
         AND source = 'gateway'
         AND (context IS NULL OR context->>'utm_source' IS NULL OR TRIM(COALESCE(context->>'utm_source', '')) = '')${dateCondUntracked}`,
      untrackedParams
    );
    untrackedSalesCount = parseInt(rUntracked.rows[0]?.cnt, 10) || 0;
  } catch (e) {
    // ignora
  }

  // Contagem por evento de scroll (funil de engajamento)
  const scrollEventNames = ['PageView', 'scroll_25', 'scroll_50', 'scroll_75', 'scroll_100'];
  let scrollCounts = { PageView: 0, scroll_25: 0, scroll_50: 0, scroll_75: 0, scroll_100: 0 };
  try {
    const dateCondScroll = dateFrom ? ' AND created_at >= $2' : '';
    const rScroll = await pool.query(
      `SELECT event_name, COUNT(*) AS cnt
       FROM normalized_events
       WHERE event_name = ANY($1::text[])${dateCondScroll}
       GROUP BY event_name`,
      dateFrom ? [scrollEventNames, dateFrom.toISOString()] : [scrollEventNames]
    );
    rScroll.rows.forEach((row) => {
      if (Object.prototype.hasOwnProperty.call(scrollCounts, row.event_name)) {
        scrollCounts[row.event_name] = parseInt(row.cnt, 10) || 0;
      }
    });
  } catch (e) {
    // ignora
  }

  let totalEvents = 0;
  let totalPurchases = 0;
  let totalValue = 0;
  projects.forEach((p) => {
    const s = statsByProject[p.id] || { total_events: 0, purchases: 0, total_value: 0 };
    totalEvents += s.total_events;
    totalPurchases += s.purchases;
    totalValue += s.total_value;
  });
  const totalCost = Object.values(costByUtm).reduce((a, b) => a + b, 0);
  const totalValueStr = totalValue > 0 ? 'R$ ' + Number(totalValue).toFixed(2).replace('.', ',') : '0';
  const cpaStr = totalPurchases > 0 && totalCost > 0 ? 'R$ ' + Number(totalCost / totalPurchases).toFixed(2).replace('.', ',') : '—';
  const roasStr = totalCost > 0 && totalValue > 0 ? Number(totalValue / totalCost).toFixed(2).replace('.', ',') + 'x' : '—';
  const convRateStr = totalEvents > 0 && totalPurchases > 0 ? Number((totalPurchases / totalEvents) * 100).toFixed(2).replace('.', ',') + '%' : '—';
  const kpiCardsHtml =
    `<div class="kpi-grid">
      <div class="kpi-card" title="Total de eventos (PageView, Purchase, etc.)"><div class="kpi-card__value">${totalEvents}</div><div class="kpi-card__label">Eventos</div></div>
      <div class="kpi-card" title="Total de compras (Purchase)"><div class="kpi-card__value">${totalPurchases}</div><div class="kpi-card__label">Compras</div></div>
      <div class="kpi-card" title="Soma do valor das compras"><div class="kpi-card__value">${totalValueStr}</div><div class="kpi-card__label">Valor total</div></div>
      <div class="kpi-card" title="Custo por aquisição (custo total ÷ compras)"><div class="kpi-card__value">${cpaStr}</div><div class="kpi-card__label">CPA</div></div>
      <div class="kpi-card" title="Retorno sobre gasto em anúncios (valor ÷ custo)"><div class="kpi-card__value">${roasStr}</div><div class="kpi-card__label">ROAS</div></div>
      <div class="kpi-card" title="Taxa de conversão (compras ÷ eventos × 100)"><div class="kpi-card__value">${convRateStr}</div><div class="kpi-card__label">Taxa conv.</div></div>
    </div>
    <p class="metrics-legend">CPA = Custo por aquisição · ROAS = Retorno sobre gasto em ads · Taxa conv. = Compras/Eventos. <span title="CPC (custo por clique) e CTR exigem dados de cliques/impressões do Meta Ads.">CPC/CTR</span> exigem integração com Meta Ads.</p>`;

  const summaryRows = projects
    .map((p) => {
      const s = statsByProject[p.id] || { total_events: 0, purchases: 0, total_value: 0 };
      const valueStr = s.total_value > 0 ? 'R$ ' + Number(s.total_value).toFixed(2).replace('.', ',') : '—';
      const eventsUrl = '/painel/events/' + p.id + (adminKey ? '?key=' + encodeURIComponent(adminKey) : '');
      return `<tr><td>${escapeHtml(p.name)}</td><td>${s.total_events}</td><td>${s.purchases}</td><td>${valueStr}</td><td><a href="${escapeHtml(eventsUrl)}" class="btn btn-sm">Ver eventos</a></td></tr>`;
    })
    .join('');
  const periodQuery = period !== 'all' ? `?period=${period}` : '';
  const exportResumoUrl = '/painel/export/resumo?' + (period !== 'all' ? 'period=' + period + '&' : '') + (adminKey ? 'key=' + encodeURIComponent(adminKey) : '');
  const summaryHtml =
    `<div class="section-header"><h2 class="section-title" id="resumo">Resumo</h2>
    <div class="section-header-actions">
      <select id="periodSelect" class="period-select" title="Período">
        <option value="all" ${period === 'all' ? 'selected' : ''}>Todo o período</option>
        <option value="1d" ${period === '1d' ? 'selected' : ''}>Últimas 24h</option>
        <option value="7d" ${period === '7d' ? 'selected' : ''}>Últimos 7 dias</option>
        <option value="30d" ${period === '30d' ? 'selected' : ''}>Últimos 30 dias</option>
      </select>
      <a href="${escapeHtml(exportResumoUrl)}" class="btn btn-sm">Exportar resumo (CSV)</a>
    </div></div>
    <div class="dashboard-table-wrap">
    <table class="dashboard-table">
      <thead><tr><th>Projeto</th><th>Eventos</th><th>Compras</th><th>Valor total</th><th></th></tr></thead>
      <tbody>${summaryRows || '<tr><td colspan="5" class="events-empty">Nenhum projeto com eventos no período.</td></tr>'}</tbody>
    </table>
    </div>`;

  const pv = scrollCounts.PageView || 1;
  const pct25 = scrollCounts.scroll_25;
  const pct50 = scrollCounts.scroll_50;
  const pct75 = scrollCounts.scroll_75;
  const pct100 = scrollCounts.scroll_100;
  const scrollFunnelHtml =
    `<div class="scroll-funnel-section">
    <h3 class="section-subtitle">Engajamento (scroll)</h3>
    <p class="dashboard-lead dashboard-lead--compact">Até onde os visitantes rolaram a página (eventos scroll 25%, 50%, 75%, 100% no período).</p>
    <div class="scroll-funnel">
      <div class="scroll-funnel__step" title="Visualizações de página">
        <div class="scroll-funnel__label">PageView</div>
        <div class="scroll-funnel__value">${scrollCounts.PageView}</div>
        <div class="scroll-funnel__pct">100%</div>
      </div>
      <div class="scroll-funnel__arrow" aria-hidden="true">→</div>
      <div class="scroll-funnel__step" title="Rolaram até 25%">
        <div class="scroll-funnel__label">25%</div>
        <div class="scroll-funnel__value">${pct25}</div>
        <div class="scroll-funnel__pct">${pv ? Math.round((pct25 / pv) * 100) : 0}%</div>
      </div>
      <div class="scroll-funnel__arrow" aria-hidden="true">→</div>
      <div class="scroll-funnel__step" title="Rolaram até 50%">
        <div class="scroll-funnel__label">50%</div>
        <div class="scroll-funnel__value">${pct50}</div>
        <div class="scroll-funnel__pct">${pv ? Math.round((pct50 / pv) * 100) : 0}%</div>
      </div>
      <div class="scroll-funnel__arrow" aria-hidden="true">→</div>
      <div class="scroll-funnel__step" title="Rolaram até 75%">
        <div class="scroll-funnel__label">75%</div>
        <div class="scroll-funnel__value">${pct75}</div>
        <div class="scroll-funnel__pct">${pv ? Math.round((pct75 / pv) * 100) : 0}%</div>
      </div>
      <div class="scroll-funnel__arrow" aria-hidden="true">→</div>
      <div class="scroll-funnel__step" title="Rolaram até 100%">
        <div class="scroll-funnel__label">100%</div>
        <div class="scroll-funnel__value">${pct100}</div>
        <div class="scroll-funnel__pct">${pv ? Math.round((pct100 / pv) * 100) : 0}%</div>
      </div>
    </div>
    </div>`;

  const tabsHtml = `
    <div class="dashboard-tabs" role="tablist">
      <button type="button" class="dashboard-tab active" role="tab" id="tab-resumo" aria-selected="true" aria-controls="panel-resumo">Resumo</button>
      <button type="button" class="dashboard-tab" role="tab" id="tab-campanhas" aria-selected="false" aria-controls="panel-campanhas">Campanhas</button>
    </div>
    <div class="dashboard-tabs-panel" id="panel-resumo" role="tabpanel" aria-labelledby="tab-resumo">
      ${kpiCardsHtml}
      ${summaryHtml}
      ${scrollFunnelHtml}
    </div>
    ${campaignPanelHtml}`;

  const dashboardContent =
    (untrackedSalesCount > 0 ? `<div class="alert alert-warning" id="alert-untracked">
      <strong>${untrackedSalesCount} venda${untrackedSalesCount !== 1 ? 's' : ''} não trackeada${untrackedSalesCount !== 1 ? 's' : ''}.</strong>
      Compras que chegaram pelo gateway (ex.: Kiwify) sem UTM — não é possível atribuir a uma campanha.
    </div>` : '') +
    tabsHtml;

  const dashboardHeaderRight =
    `<span class="dashboard-updated">Atualizado em ${new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}</span>
     <a href="/painel${period !== 'all' ? '?period=' + period : ''}${adminKey ? (period !== 'all' ? '&' : '?') + 'key=' + encodeURIComponent(adminKey) : ''}" class="btn btn-sm btn-primary">Atualizar</a>
     <span class="dashboard-user">Admin</span>`;

  const dashboardScripts = `
  <script>
    var adminKey = ${JSON.stringify(adminKey)};
    var sel = document.getElementById('periodSelect');
    if (sel) sel.addEventListener('change', function() {
      var v = this.value;
      var q = v !== 'all' ? '?period=' + v : '';
      if (adminKey) q += (q ? '&' : '?') + 'key=' + encodeURIComponent(adminKey);
      window.location.href = '/painel' + q;
    });
    (function() {
      var tabResumo = document.getElementById('tab-resumo');
      var tabCampanhas = document.getElementById('tab-campanhas');
      var panelResumo = document.getElementById('panel-resumo');
      var panelCampanhas = document.getElementById('panel-campanhas');
      function showResumo() {
        if (panelResumo) { panelResumo.style.display = ''; panelResumo.setAttribute('aria-hidden', 'false'); }
        if (panelCampanhas) { panelCampanhas.style.display = 'none'; panelCampanhas.setAttribute('aria-hidden', 'true'); }
        if (tabResumo) { tabResumo.classList.add('active'); tabResumo.setAttribute('aria-selected', 'true'); }
        if (tabCampanhas) { tabCampanhas.classList.remove('active'); tabCampanhas.setAttribute('aria-selected', 'false'); }
      }
      function showCampanhas() {
        if (panelResumo) { panelResumo.style.display = 'none'; panelResumo.setAttribute('aria-hidden', 'true'); }
        if (panelCampanhas) { panelCampanhas.style.display = ''; panelCampanhas.setAttribute('aria-hidden', 'false'); }
        if (tabResumo) { tabResumo.classList.remove('active'); tabResumo.setAttribute('aria-selected', 'false'); }
        if (tabCampanhas) { tabCampanhas.classList.add('active'); tabCampanhas.setAttribute('aria-selected', 'true'); }
      }
      if (tabResumo) tabResumo.addEventListener('click', showResumo);
      if (tabCampanhas) tabCampanhas.addEventListener('click', showCampanhas);
    })();
    document.querySelectorAll('.btn-save-cost').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var row = btn.closest('tr');
        if (!row) return;
        var us = row.getAttribute('data-us') || '';
        var um = row.getAttribute('data-um') || '';
        var uc = row.getAttribute('data-uc') || '';
        var input = row.querySelector('.input-cost');
        var cost = input ? parseFloat(input.value) : 0;
        if (Number.isNaN(cost)) cost = 0;
        var headers = { 'Content-Type': 'application/json' };
        if (adminKey) headers['X-Admin-Key'] = adminKey;
        fetch('/api/campaign-cost', { method: 'PUT', headers: headers, credentials: 'same-origin',
          body: JSON.stringify({ utm_source: us, utm_medium: um, utm_campaign: uc, cost: cost }) })
          .then(function(r) {
            if (r.ok) { window.location.reload(); return; }
            return r.json().then(function(d) { throw new Error(d.error || 'Erro ao salvar'); });
          }).catch(function(err) { alert(err.message); });
      });
    });
  </script>`;

  const html = painelLayout({
    activeNav: 'dashboard',
    title: 'Dashboard - Principal',
    headerLogo: 'Tracking Core',
    headerRight: dashboardHeaderRight,
    content: dashboardContent,
    adminKey,
    extraScripts: dashboardScripts
  });
  res.type('html').send(html);
}));

// Página Projetos: criar, listar, editar, ativar/desativar
app.get('/painel/projetos', asyncHandler(async (req, res) => {
  if (!ADMIN_SECRET) return res.status(503).send('Painel desativado. Configure ADMIN_SECRET.');
  if (!isAdminAuthorized(req)) return res.redirect(302, '/login');
  if (!pool) return res.status(503).send('Banco não configurado.');
  if (req.query.key === ADMIN_SECRET) setAdminCookie(res);
  const baseUrl = BASE_URL || `${req.protocol}://${req.get('host')}`;
  const adminKey = req.query.key || '';

  let projects = [];
  try {
    const r = await pool.query(
      `SELECT p.id, p.name, p.api_key_public, p.api_key_secret, p.webhook_out_url,
              COALESCE(p.enabled_conversions, '["PageView"]'::jsonb) AS enabled_conversions,
              EXISTS(SELECT 1 FROM integrations_meta m WHERE m.project_id = p.id AND m.active) AS has_meta
       FROM projects p WHERE p.status = 'active' ORDER BY p.created_at DESC`
    );
    projects = r.rows.map((row) => {
      const rawConv = row.enabled_conversions;
      const enabledList = Array.isArray(rawConv) && rawConv.length ? rawConv : ['PageView'];
      const snippets = {};
      CONVERSION_CATALOG.forEach((c) => {
        snippets[c.key] = buildConversionSnippet(c.key, baseUrl, row.api_key_public);
      });
      const fullScript = buildFullScript(enabledList, baseUrl, row.api_key_public);
      return {
        id: row.id,
        name: row.name,
        api_key_public: row.api_key_public,
        api_key_secret: row.api_key_secret,
        webhook_out_url: row.webhook_out_url || '',
        has_meta: row.has_meta,
        enabled_conversions: enabledList,
        snippets,
        full_script: fullScript,
        script_snippet: `<script src="${baseUrl}/sdk/browser-tracker.js"></script>
<script>
  (function(){
    var t = TrackingCore.createTracker({
      endpoint: '${baseUrl}/events',
      apiKey: '${row.api_key_public}'
    });
    t.trackPageView();
  })();
</script>`,
        webhook_url: `${baseUrl}/webhooks/kiwify?project_key=${encodeURIComponent(row.api_key_secret)}`
      };
    });
  } catch (e) {
    if (e.message && e.message.includes('enabled_conversions')) {
      try {
        const r = await pool.query(
          `SELECT p.id, p.name, p.api_key_public, p.api_key_secret, p.webhook_out_url,
                  EXISTS(SELECT 1 FROM integrations_meta m WHERE m.project_id = p.id AND m.active) AS has_meta
           FROM projects p WHERE p.status = 'active' ORDER BY p.created_at DESC`
        );
        projects = r.rows.map((row) => {
          const snippets = {};
          CONVERSION_CATALOG.forEach((c) => {
            snippets[c.key] = buildConversionSnippet(c.key, baseUrl, row.api_key_public);
          });
          return {
            id: row.id,
            name: row.name,
            api_key_public: row.api_key_public,
            api_key_secret: row.api_key_secret,
            webhook_out_url: row.webhook_out_url || '',
            has_meta: row.has_meta,
            enabled_conversions: ['PageView'],
            snippets,
            full_script: buildFullScript(['PageView'], baseUrl, row.api_key_public),
            script_snippet: `<script src="${baseUrl}/sdk/browser-tracker.js"></script>
<script>
  (function(){
    var t = TrackingCore.createTracker({
      endpoint: '${baseUrl}/events',
      apiKey: '${row.api_key_public}'
    });
    t.trackPageView();
  })();
</script>`,
            webhook_url: `${baseUrl}/webhooks/kiwify?project_key=${encodeURIComponent(row.api_key_secret)}`
          };
        });
      } catch (e2) {
        console.error('[tracking-core] Erro ao listar projetos:', e2.message);
        return res.status(500).send('Erro ao carregar projetos.');
      }
    } else {
      console.error('[tracking-core] Erro ao listar projetos:', e.message);
      return res.status(500).send('Erro ao carregar projetos.');
    }
  }

  let inactiveProjects = [];
  try {
    const rInactive = await pool.query(
      `SELECT id, name FROM projects WHERE status = 'inactive' ORDER BY created_at DESC`
    );
    inactiveProjects = rInactive.rows;
  } catch (e) {}

  const projectsHtml = projects
    .map((p) => {
      const enabledSet = new Set(p.enabled_conversions || ['PageView']);
      const checkboxes = CONVERSION_CATALOG.map(
        (c) =>
          `<label class="conversion-check"><input type="checkbox" class="conversion-cb" data-key="${escapeHtml(c.key)}" ${enabledSet.has(c.key) ? 'checked' : ''}> ${conversionLabelWithTooltip(c)}</label>`
      ).join('');
      const snippetBlocks = (p.enabled_conversions || ['PageView'])
        .filter((k) => p.snippets && p.snippets[k])
        .map((k) => {
          const catalogEntry = CONVERSION_CATALOG.find((c) => c.key === k);
          const labelHtml = catalogEntry ? conversionLabelWithTooltip(catalogEntry) : escapeHtml(k);
          const inlineCode = buildInlineSnippet(k);
          return `<span class="label">${labelHtml}</span>
      <p class="snippet-hint">Script para header ou body (carrega tudo de uma vez):</p>
      <div class="copy-wrap"><pre class="snippet snippet-sm">${escapeHtml(p.snippets[k])}</pre>
      <button type="button" class="btn btn-sm" data-copy="${escapeHtml((p.snippets || {})[k] || '')}">Copiar script</button></div>
      <p class="snippet-hint">Para colar em um botão ou elemento (use depois do script principal no site):</p>
      <div class="copy-wrap"><pre class="snippet snippet-sm snippet-inline">${escapeHtml(inlineCode)}</pre>
      <button type="button" class="btn btn-sm" data-copy="${escapeHtml(inlineCode)}">Copiar</button></div>`;
        })
        .join('');
      return `
    <div class="card" data-project-id="${escapeHtml(p.id)}">
      <div class="card-header">
        <h2 class="card-title">${escapeHtml(p.name)} ${p.has_meta ? '<span class="badge">Meta</span>' : ''}</h2>
        <div class="card-actions">
          <a href="/painel/events/${escapeHtml(p.id)}?key=${encodeURIComponent(adminKey || '')}" class="btn btn-sm">Ver eventos</a>
          <button type="button" class="btn btn-sm btn-test-event" data-id="${escapeHtml(p.id)}">Testar evento</button>
          <button type="button" class="btn btn-sm btn-edit" data-id="${escapeHtml(p.id)}" data-name="${escapeHtml(p.name)}" data-webhook-out="${escapeHtml(p.webhook_out_url || '')}">Editar</button>
          <button type="button" class="btn btn-sm btn-danger btn-deactivate" data-id="${escapeHtml(p.id)}" data-name="${escapeHtml(p.name)}">Desativar</button>
        </div>
      </div>
      ${p.webhook_out_url ? `<span class="label">Webhook de saída (compras)</span><p style="margin:0 0 1rem 0;font-size:0.85rem;"><code>${escapeHtml(p.webhook_out_url)}</code></p>` : ''}
      <div class="conversions-section">
        <span class="label">Conversões a rastrear</span>
        <div class="conversion-checkboxes">${checkboxes}</div>
        <button type="button" class="btn btn-sm btn-primary btn-save-conversions" data-id="${escapeHtml(p.id)}">Salvar conversões</button>
      </div>
      <div class="codes-section">
        <span class="label">Códigos de rastreamento</span>
        <p class="snippet-hint">Cada conversão: script para header/body e código para colar em botão ou elemento.</p>
        ${snippetBlocks}
        <span class="label">Script completo (header ou body) – todas as conversões selecionadas</span>
        <div class="copy-wrap">
          <pre class="snippet">${escapeHtml(p.full_script || p.script_snippet)}</pre>
          <button type="button" class="btn btn-sm" data-copy="${escapeHtml(p.full_script || p.script_snippet)}">Copiar script completo</button>
        </div>
      </div>
      <span class="label">Chave pública</span>
      <p style="margin:0 0 1rem 0;"><code>${escapeHtml(p.api_key_public)}</code></p>
      <span class="label">URL webhook Kiwify</span>
      <div class="copy-wrap">
        <pre class="snippet url">${escapeHtml(p.webhook_url)}</pre>
        <button type="button" class="btn btn-sm" data-copy="${escapeHtml(p.webhook_url)}">Copiar URL</button>
      </div>
    </div>`;
    })
    .join('');

  const inactiveHtml = inactiveProjects
    .map(
      (p) => `
    <div class="card card-inactive">
      <div class="card-header">
        <h2 class="card-title">${escapeHtml(p.name)} <span class="badge badge-inactive">Inativo</span></h2>
        <button type="button" class="btn btn-sm btn-primary btn-activate" data-id="${escapeHtml(p.id)}" data-name="${escapeHtml(p.name)}">Reativar</button>
      </div>
    </div>`
    )
    .join('');

  const formConversionCheckboxes = CONVERSION_CATALOG.map(
    (c) =>
      `<label class="conversion-check"><input type="checkbox" class="form-conversion-cb" name="conversion" value="${escapeHtml(c.key)}" ${c.key === 'PageView' ? 'checked' : ''}> ${conversionLabelWithTooltip(c)}</label>`
  ).join('');
  const projetosContent = `
    <section class="form-card">
      <h2>Novo projeto</h2>
      <form id="formNovo">
        <span class="label">Nome do projeto</span>
        <input type="text" name="name" required placeholder="Ex: Meu funil">
        <span class="label">Pixel ID (Meta) – opcional</span>
        <input type="text" name="pixel_id" placeholder="Ex: 123456789">
        <span class="label">Access Token (Meta) – opcional</span>
        <input type="password" name="access_token" placeholder="Token de acesso">
        <span class="label">Test Event Code (opcional)</span>
        <input type="text" name="test_event_code" placeholder="">
        <span class="label">Conversões a rastrear</span>
        <p class="snippet-hint">Selecione os eventos que deseja rastrear. O script será gerado com base nisso.</p>
        <div class="conversion-checkboxes">${formConversionCheckboxes}</div>
        <button type="submit" class="btn btn-primary">Criar projeto</button>
      </form>
    </section>
    <h3 class="section-subtitle">Projetos ativos</h3>
    ${projects.length ? projectsHtml : '<div class="empty-state">Nenhum projeto ativo. Crie um acima ou reative um inativo.</div>'}
    ${inactiveProjects.length ? `<h3 class="section-subtitle">Projetos inativos</h3>${inactiveHtml}` : ''}
    <div id="toast" class="toast" style="display:none;"></div>
    <div id="modalEdit" class="modal">
      <div class="modal-content">
        <span class="modal-close" id="modalEditClose" aria-label="Fechar">&times;</span>
        <h2>Editar projeto</h2>
        <form id="formEdit">
          <input type="hidden" name="id" id="editId">
          <span class="label">Nome do projeto</span>
          <input type="text" name="name" id="editName" required>
          <span class="label">Pixel ID (Meta) – opcional</span>
          <input type="text" name="pixel_id" id="editPixelId" placeholder="Deixe em branco para não alterar">
          <span class="label">Access Token (Meta) – opcional</span>
          <input type="password" name="access_token" id="editAccessToken" placeholder="Deixe em branco para não alterar">
          <span class="label">Test Event Code (opcional)</span>
          <input type="text" name="test_event_code" id="editTestEventCode">
          <span class="label">URL webhook de saída (compras) – opcional</span>
          <input type="text" name="webhook_out_url" id="editWebhookOutUrl" placeholder="https://seu-crm.com/webhook">
          <button type="submit" class="btn btn-primary">Salvar</button>
        </form>
      </div>
    </div>`;

  const projetosScripts = `
  <script>
    var adminKey = ${JSON.stringify(adminKey)};
    document.querySelectorAll('[data-copy]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var text = btn.getAttribute('data-copy');
        navigator.clipboard.writeText(text).then(function() {
          var t = document.getElementById('toast');
          t.textContent = 'Copiado!';
          t.style.display = 'block';
          setTimeout(function() { t.style.display = 'none'; }, 2000);
        });
      });
    });
    document.getElementById('formNovo').addEventListener('submit', function(e) {
      e.preventDefault();
      var form = this;
      var fd = new FormData(form);
      var payload = { name: fd.get('name') };
      if (fd.get('pixel_id')) payload.pixel_id = fd.get('pixel_id');
      if (fd.get('access_token')) payload.access_token = fd.get('access_token');
      if (fd.get('test_event_code')) payload.test_event_code = fd.get('test_event_code');
      var conversions = [];
      form.querySelectorAll('.form-conversion-cb:checked').forEach(function(cb) { if (cb.value) conversions.push(cb.value); });
      if (conversions.length) payload.enabled_conversions = conversions;
      var apiHeaders = { 'Content-Type': 'application/json' };
      if (adminKey) apiHeaders['X-Admin-Key'] = adminKey;
      fetch('/api/projects', { method: 'POST', headers: apiHeaders, credentials: 'same-origin', body: JSON.stringify(payload) })
        .then(function(r) {
          if (r.ok) return r.json();
          throw new Error(r.status === 401 ? 'Chave de admin inválida' : 'Erro ao criar projeto');
        }).then(function() { window.location.reload(); }).catch(function(err) { alert(err.message); });
    });
    var modalEdit = document.getElementById('modalEdit');
    var formEdit = document.getElementById('formEdit');
    document.querySelectorAll('.btn-edit').forEach(function(btn) {
      btn.addEventListener('click', function() {
        document.getElementById('editId').value = btn.getAttribute('data-id');
        document.getElementById('editName').value = btn.getAttribute('data-name') || '';
        document.getElementById('editPixelId').value = '';
        document.getElementById('editAccessToken').value = '';
        document.getElementById('editTestEventCode').value = '';
        document.getElementById('editWebhookOutUrl').value = btn.getAttribute('data-webhook-out') || '';
        modalEdit.classList.add('show');
      });
    });
    document.getElementById('modalEditClose').addEventListener('click', function() { modalEdit.classList.remove('show'); });
    modalEdit.addEventListener('click', function(e) { if (e.target === modalEdit) modalEdit.classList.remove('show'); });
    formEdit.addEventListener('submit', function(e) {
      e.preventDefault();
      var id = document.getElementById('editId').value;
      var payload = { name: document.getElementById('editName').value.trim() };
      var pid = document.getElementById('editPixelId').value.trim();
      var tok = document.getElementById('editAccessToken').value.trim();
      if (pid) payload.pixel_id = pid;
      if (tok) payload.access_token = tok;
      var tec = document.getElementById('editTestEventCode').value.trim();
      if (tec) payload.test_event_code = tec;
      payload.webhook_out_url = document.getElementById('editWebhookOutUrl').value.trim();
      var patchHeaders = { 'Content-Type': 'application/json' };
      if (adminKey) patchHeaders['X-Admin-Key'] = adminKey;
      fetch('/api/projects/' + encodeURIComponent(id), { method: 'PATCH', headers: patchHeaders, credentials: 'same-origin', body: JSON.stringify(payload) })
        .then(function(r) {
          if (r.ok) { modalEdit.classList.remove('show'); window.location.reload(); return; }
          return r.json().then(function(d) { throw new Error(d.error || 'Erro ao salvar'); });
        }).catch(function(err) { alert(err.message); });
    });
    document.querySelectorAll('.btn-deactivate').forEach(function(btn) {
      btn.addEventListener('click', function() {
        if (!confirm('Desativar o projeto \\"' + (btn.getAttribute('data-name') || '') + '\\"? O script e o webhook pararão de aceitar eventos.')) return;
        var id = btn.getAttribute('data-id');
        var headers = {};
        if (adminKey) headers['X-Admin-Key'] = adminKey;
        fetch('/api/projects/' + encodeURIComponent(id) + '/deactivate', { method: 'POST', headers: headers, credentials: 'same-origin' })
          .then(function(r) {
            if (r.ok) { window.location.reload(); return; }
            return r.json().then(function(d) { throw new Error(d.error || 'Erro ao desativar'); });
          }).catch(function(err) { alert(err.message); });
      });
    });
    document.querySelectorAll('.btn-activate').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var id = btn.getAttribute('data-id');
        var headers = {};
        if (adminKey) headers['X-Admin-Key'] = adminKey;
        fetch('/api/projects/' + encodeURIComponent(id) + '/activate', { method: 'POST', headers: headers, credentials: 'same-origin' })
          .then(function(r) {
            if (r.ok) { window.location.reload(); return; }
            return r.json().then(function(d) { throw new Error(d.error || 'Erro ao reativar'); });
          }).catch(function(err) { alert(err.message); });
      });
    });
    document.querySelectorAll('.btn-test-event').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var id = btn.getAttribute('data-id');
        var headers = {};
        if (adminKey) headers['X-Admin-Key'] = adminKey;
        btn.disabled = true;
        fetch('/api/projects/' + encodeURIComponent(id) + '/test-event', { method: 'POST', headers: headers, credentials: 'same-origin' })
          .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
          .then(function(o) {
            btn.disabled = false;
            var t = document.getElementById('toast');
            if (o.ok) { t.textContent = 'Evento de teste enviado!'; t.style.display = 'block'; setTimeout(function() { t.style.display = 'none'; }, 3000); }
            else { alert(o.data.error || 'Erro ao enviar evento'); }
          }).catch(function(err) { btn.disabled = false; alert(err.message); });
      });
    });
    document.querySelectorAll('.btn-save-conversions').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var id = btn.getAttribute('data-id');
        var card = btn.closest('.card');
        if (!card) return;
        var keys = [];
        card.querySelectorAll('.conversion-cb:checked').forEach(function(cb) {
          var k = cb.getAttribute('data-key');
          if (k) keys.push(k);
        });
        if (keys.length === 0) keys = ['PageView'];
        var headers = { 'Content-Type': 'application/json' };
        if (adminKey) headers['X-Admin-Key'] = adminKey;
        btn.disabled = true;
        fetch('/api/projects/' + encodeURIComponent(id), {
          method: 'PATCH',
          headers: headers,
          credentials: 'same-origin',
          body: JSON.stringify({ enabled_conversions: keys })
        }).then(function(r) {
          btn.disabled = false;
          if (r.ok) { window.location.reload(); return; }
          return r.json().then(function(d) { throw new Error(d.error || 'Erro ao salvar'); });
        }).catch(function(err) { alert(err.message); });
      });
    });
  </script>`;

  const html = painelLayout({
    activeNav: 'projetos',
    title: 'Projetos',
    headerRight: '<span class="dashboard-user">Admin</span>',
    content: projetosContent,
    adminKey,
    extraScripts: projetosScripts
  });
  res.type('html').send(html);
}));

// Página Pixel: listar conexões Meta e conectar/editar pixel por projeto
app.get('/painel/pixel', asyncHandler(async (req, res) => {
  if (!ADMIN_SECRET) return res.status(503).send('Painel desativado.');
  if (!isAdminAuthorized(req)) return res.redirect(302, '/login');
  if (!pool) return res.status(503).send('Banco não configurado.');
  if (req.query.key === ADMIN_SECRET) setAdminCookie(res);
  const adminKey = req.query.key || '';

  let pixels = [];
  try {
    const r = await pool.query(
      `SELECT p.id AS project_id, p.name AS project_name,
              m.pixel_id, m.test_event_code, m.active
       FROM projects p
       LEFT JOIN integrations_meta m ON m.project_id = p.id AND m.active = true
       WHERE p.status = 'active'
       ORDER BY p.name`
    );
    pixels = r.rows;
  } catch (e) {
    console.error('[tracking-core] Erro ao listar pixels:', e.message);
    return res.status(500).send('Erro ao carregar conexões.');
  }

  const rows = pixels
    .map(
      (row) => `
    <tr>
      <td>${escapeHtml(row.project_name)}</td>
      <td>${row.pixel_id ? escapeHtml(row.pixel_id) : '<span class="text-muted">—</span>'}</td>
      <td>${row.pixel_id ? '<span class="badge">Conectado</span>' : '<span class="badge badge-inactive">Não conectado</span>'}</td>
      <td><a href="/painel/projetos${adminKey ? '?key=' + encodeURIComponent(adminKey) : ''}" class="btn btn-sm">${row.pixel_id ? 'Editar' : 'Conectar'}</a></td>
    </tr>`
    )
    .join('');

  const pixelContent = `
    <p class="dashboard-lead">Conexões Meta (Pixel) por projeto. Para conectar ou alterar um pixel, use <strong>Conectar</strong> ou <strong>Editar</strong> e preencha na página de Projetos (ao editar o projeto) ou conecte ao criar um novo projeto.</p>
    <div class="dashboard-table-wrap">
      <table class="dashboard-table">
        <thead><tr><th>Projeto</th><th>Pixel ID</th><th>Status</th><th>Ações</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="4" class="events-empty">Nenhum projeto ativo.</td></tr>'}</tbody>
      </table>
    </div>`;

  const html = painelLayout({
    activeNav: 'pixel',
    title: 'Pixel',
    headerRight: '<span class="dashboard-user">Admin</span>',
    content: pixelContent,
    adminKey
  });
  res.type('html').send(html);
}));

// ---------- Meta Ads (Marketing API): OAuth + listar campanhas e gastos ----------
const META_ADS_SCOPE = 'ads_read';
const META_GRAPH_VERSION = 'v18.0';

function metaAdsStateCookieName() {
  return 'meta_ads_state';
}

function createMetaAdsState() {
  const state = crypto.randomBytes(16).toString('hex');
  const sign = crypto.createHmac('sha256', ADMIN_SECRET || 'meta-ads').update(state).digest('hex');
  return state + '.' + sign.slice(0, 8);
}

function verifyMetaAdsState(req, stateFromQuery) {
  const raw = getCookie(req, metaAdsStateCookieName());
  if (!raw || !stateFromQuery || raw !== stateFromQuery) return false;
  const idx = raw.lastIndexOf('.');
  const state = idx >= 0 ? raw.slice(0, idx) : raw;
  const sig = idx >= 0 ? raw.slice(idx + 1) : '';
  const expected = crypto.createHmac('sha256', ADMIN_SECRET || 'meta-ads').update(state).digest('hex').slice(0, 8);
  return sig === expected;
}

// Redireciona para o OAuth da Meta
app.get('/painel/meta-ads/connect', (req, res) => {
  if (!ADMIN_SECRET) return res.status(503).send('Painel desativado.');
  if (!isAdminAuthorized(req)) return res.redirect(302, '/login');
  if (!hasMetaAdsOAuthConfig) {
    return res.redirect(302, '/painel/meta-ads?key=' + encodeURIComponent(req.query.key || '') + '&error=config');
  }
  const state = createMetaAdsState();
  const redirectUri = BASE_URL + '/painel/meta-ads/callback';
  res.cookie(metaAdsStateCookieName(), state, { httpOnly: true, maxAge: 600, sameSite: 'lax' });
  const url = `https://www.facebook.com/${META_GRAPH_VERSION}/dialog/oauth?client_id=${encodeURIComponent(META_ADS_APP_ID)}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(META_ADS_SCOPE)}&state=${encodeURIComponent(state)}`;
  res.redirect(302, url);
});

// Callback OAuth: troca code por token, obtém conta de anúncios, grava conexão
app.get('/painel/meta-ads/callback', asyncHandler(async (req, res) => {
  if (!ADMIN_SECRET || !pool) return res.redirect(302, '/painel/meta-ads?error=server');
  const state = req.query.state;
  const code = req.query.code;
  const adminKey = req.query.key || '';
  const q = adminKey ? '?key=' + encodeURIComponent(adminKey) : '';
  if (!code || !verifyMetaAdsState(req, state)) {
    return res.redirect(302, '/painel/meta-ads' + q + '&error=oauth');
  }
  res.clearCookie(metaAdsStateCookieName());
  const redirectUri = BASE_URL + '/painel/meta-ads/callback';
  try {
    const tokenRes = await axios.get(`https://graph.facebook.com/${META_GRAPH_VERSION}/oauth/access_token`, {
      params: {
        client_id: META_ADS_APP_ID,
        client_secret: META_ADS_APP_SECRET,
        redirect_uri: redirectUri,
        code
      }
    });
    let accessToken = tokenRes.data?.access_token;
    if (!accessToken) {
      return res.redirect(302, '/painel/meta-ads' + q + '&error=token');
    }
    // Trocar por long-lived token (opcional mas recomendado)
    try {
      const longLived = await axios.get(`https://graph.facebook.com/${META_GRAPH_VERSION}/oauth/access_token`, {
        params: {
          grant_type: 'fb_exchange_token',
          client_id: META_ADS_APP_ID,
          client_secret: META_ADS_APP_SECRET,
          fb_exchange_token: accessToken
        }
      });
      if (longLived.data?.access_token) accessToken = longLived.data.access_token;
    } catch (_) {
      // mantém short-lived se falhar
    }
    const adAccountsRes = await axios.get(`https://graph.facebook.com/${META_GRAPH_VERSION}/me/adaccounts`, {
      params: { fields: 'id,name,account_id', access_token: accessToken }
    });
    const accounts = adAccountsRes.data?.data || [];
    if (accounts.length === 0) {
      return res.redirect(302, '/painel/meta-ads' + q + '&error=no_accounts');
    }
    const adAccount = accounts[0];
    const adAccountId = adAccount.id || adAccount.account_id;
    const adAccountName = adAccount.name || null;
    const tenantRow = await pool.query('SELECT id FROM tenants WHERE status = $1 ORDER BY created_at LIMIT 1', ['active']);
    const tenantId = tenantRow.rows[0]?.id;
    if (!tenantId) {
      return res.redirect(302, '/painel/meta-ads' + q + '&error=no_tenant');
    }
    await pool.query(
      `INSERT INTO meta_ads_connections (tenant_id, ad_account_id, ad_account_name, access_token)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (tenant_id) DO UPDATE SET ad_account_id = $2, ad_account_name = $3, access_token = $4`,
      [tenantId, adAccountId, adAccountName, accessToken]
    );
    return res.redirect(302, '/painel/meta-ads' + q);
  } catch (e) {
    console.error('[tracking-core] Meta Ads callback error:', e.response?.data || e.message);
    return res.redirect(302, '/painel/meta-ads' + q + '&error=api');
  }
}));

// Busca campanhas e insights (gastos) na API da Meta
async function fetchMetaAdsCampaigns(adAccountId, accessToken, datePreset = 'last_30d') {
  const base = `https://graph.facebook.com/${META_GRAPH_VERSION}`;
  const campaignsRes = await axios.get(`${base}/${adAccountId}/campaigns`, {
    params: {
      fields: 'id,name,status,effective_status',
      access_token: accessToken
    }
  });
  const campaigns = campaignsRes.data?.data || [];
  const insightsRes = await axios.get(`${base}/${adAccountId}/insights`, {
    params: {
      level: 'campaign',
      fields: 'campaign_id,campaign_name,spend,impressions,clicks',
      date_preset: datePreset,
      access_token: accessToken
    }
  });
  const insights = insightsRes.data?.data || [];
  const spendByCampaign = {};
  insights.forEach((row) => {
    const id = row.campaign_id;
    if (id) spendByCampaign[id] = { spend: parseFloat(row.spend) || 0, impressions: parseInt(row.impressions, 10) || 0, clicks: parseInt(row.clicks, 10) || 0 };
  });
  return campaigns.map((c) => ({
    id: c.id,
    name: c.name || '—',
    status: c.effective_status || c.status || '—',
    spend: spendByCampaign[c.id]?.spend ?? 0,
    impressions: spendByCampaign[c.id]?.impressions ?? 0,
    clicks: spendByCampaign[c.id]?.clicks ?? 0
  }));
}

// Página Meta Ads: conectar ou listar campanhas com gastos
app.get('/painel/meta-ads', asyncHandler(async (req, res) => {
  if (!ADMIN_SECRET) return res.status(503).send('Painel desativado.');
  if (!isAdminAuthorized(req)) return res.redirect(302, '/login');
  if (req.query.key === ADMIN_SECRET) setAdminCookie(res);
  const adminKey = req.query.key || '';
  const q = adminKey ? '?key=' + encodeURIComponent(adminKey) : '';

  let connection = null;
  let campaigns = [];
  let errorMsg = '';
  const err = req.query.error;
  if (err === 'config') errorMsg = 'Configure META_ADS_APP_ID, META_ADS_APP_SECRET e BASE_URL no .env para usar a integração Meta Ads.';
  else if (err === 'oauth') errorMsg = 'Falha na autorização OAuth (state inválido ou expirado).';
  else if (err === 'token') errorMsg = 'Não foi possível obter o token de acesso.';
  else if (err === 'no_accounts') errorMsg = 'Nenhuma conta de anúncios encontrada na sua conta Meta.';
  else if (err === 'no_tenant') errorMsg = 'Nenhum tenant ativo no banco. Execute o seed ou crie um tenant.';
  else if (err === 'api') errorMsg = 'Erro ao comunicar com a API da Meta. Tente novamente.';

  if (pool) {
    try {
      const connRow = await pool.query(
        'SELECT id, ad_account_id, ad_account_name, access_token FROM meta_ads_connections ORDER BY created_at DESC LIMIT 1'
      );
      connection = connRow.rows[0] || null;
      if (connection) {
        const datePreset = req.query.period === '7d' ? 'last_7d' : req.query.period === '1d' ? 'today' : 'last_30d';
        try {
          campaigns = await fetchMetaAdsCampaigns(connection.ad_account_id, connection.access_token, datePreset);
        } catch (apiErr) {
          console.error('[tracking-core] Meta Ads API error:', apiErr.message);
          errorMsg = errorMsg || 'Erro ao carregar campanhas da API da Meta. Tente novamente.';
        }
      }
    } catch (e) {
      if (e.code === '42P01') {
        errorMsg = 'Tabela meta_ads_connections não existe. Rode o script sql/meta_ads.sql no banco.';
      } else {
        console.error('[tracking-core] Meta Ads:', e.message);
        errorMsg = errorMsg || 'Erro ao carregar conexão ou campanhas.';
      }
    }
  }

  const periodLinks = [
    { label: 'Hoje', period: '1d' },
    { label: '7 dias', period: '7d' },
    { label: '30 dias', period: '30d' }
  ];
  const currentPeriod = req.query.period || '30d';
  const periodBar = periodLinks.map((p) => `<a href="/painel/meta-ads?period=${p.period}${adminKey ? '&key=' + encodeURIComponent(adminKey) : ''}" class="btn btn-sm ${currentPeriod === p.period ? 'btn-primary' : ''}">${p.label}</a>`).join(' ');

  let content = '';
  if (errorMsg) {
    content += `<div class="alert alert-warning">${escapeHtml(errorMsg)}</div>`;
  }
  if (!connection) {
    content += `<p class="dashboard-lead">Conecte sua conta Meta para listar campanhas e gastos diretamente da API. Requer um app em <a href="https://developers.facebook.com" target="_blank" rel="noopener">developers.facebook.com</a> com permissão <code>ads_read</code>.</p>`;
    if (hasMetaAdsOAuthConfig) {
      content += `<p><a href="/painel/meta-ads/connect${adminKey ? '?key=' + encodeURIComponent(adminKey) : ''}" class="btn btn-primary">Conectar Meta Ads</a></p>`;
    } else {
      content += `<p class="text-muted">Configure <code>META_ADS_APP_ID</code>, <code>META_ADS_APP_SECRET</code> e <code>BASE_URL</code> no .env para habilitar o botão de conexão.</p>`;
    }
  } else {
    content += `<p class="dashboard-lead">Conta de anúncios: <strong>${escapeHtml(connection.ad_account_name || connection.ad_account_id)}</strong>. <a href="/painel/meta-ads/disconnect${adminKey ? '?key=' + encodeURIComponent(adminKey) : ''}" class="btn btn-sm" onclick="return confirm('Desconectar?');">Desconectar</a></p>`;
    content += `<div class="section-header-actions" style="margin-bottom:1rem">Período: ${periodBar}</div>`;
    content += `<div class="dashboard-table-wrap"><table class="dashboard-table dashboard-table-campaigns">
      <thead><tr><th>Campanha</th><th>Status</th><th>Gastos</th><th>Impressões</th><th>Cliques</th></tr></thead>
      <tbody>`;
    campaigns.forEach((c) => {
      const spendStr = c.spend > 0 ? 'R$ ' + Number(c.spend).toFixed(2).replace('.', ',') : 'R$ 0,00';
      content += `<tr><td><span class="campaign-name">${escapeHtml(c.name)}</span></td><td>${escapeHtml(c.status)}</td><td>${spendStr}</td><td>${c.impressions}</td><td>${c.clicks}</td></tr>`;
    });
    if (campaigns.length === 0) content += '<tr><td colspan="5" class="events-empty">Nenhuma campanha no período ou sem dados de insights.</td></tr>';
    content += '</tbody></table></div>';
  }

  const html = painelLayout({
    activeNav: 'meta_ads',
    title: 'Meta Ads',
    headerRight: '<span class="dashboard-user">Admin</span>',
    content,
    adminKey
  });
  res.type('html').send(html);
}));

// Desconectar Meta Ads (remove token)
app.get('/painel/meta-ads/disconnect', asyncHandler(async (req, res) => {
  if (!ADMIN_SECRET) return res.status(503).send('Painel desativado.');
  if (!isAdminAuthorized(req)) return res.redirect(302, '/login');
  const adminKey = req.query.key || '';
  const q = adminKey ? '?key=' + encodeURIComponent(adminKey) : '';
  if (pool) {
    try {
      await pool.query('DELETE FROM meta_ads_connections');
    } catch (_) {}
  }
  res.redirect(302, '/painel/meta-ads' + q);
}));

// Exportar resumo (projetos + UTM) em CSV
app.get('/painel/export/resumo', async (req, res) => {
  if (!ADMIN_SECRET) return res.status(503).send('Painel desativado.');
  if (!isAdminAuthorized(req)) return res.redirect(302, '/login');
  if (!pool) return res.status(503).send('Banco não configurado.');
  const period = req.query.period || 'all';
  let dateFrom = null;
  if (period === '1d') dateFrom = new Date(Date.now() - 24 * 60 * 60 * 1000);
  else if (period === '7d') dateFrom = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  else if (period === '30d') dateFrom = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  let projects = [];
  try {
    const r = await pool.query(
      `SELECT id, name FROM projects WHERE status = 'active' ORDER BY created_at DESC`
    );
    projects = r.rows;
  } catch (e) {
    return res.status(500).send('Erro ao carregar projetos.');
  }
  let statsByProject = {};
  try {
    const dateCondition = dateFrom ? ' AND created_at >= $1' : '';
    const params = dateFrom ? [dateFrom.toISOString()] : [];
    const rStats = await pool.query(
      `SELECT project_id, COUNT(*) AS total_events,
              COUNT(*) FILTER (WHERE event_name = 'Purchase') AS purchases,
              COALESCE(SUM(value) FILTER (WHERE event_name = 'Purchase'), 0) AS total_value
       FROM normalized_events WHERE 1=1${dateCondition} GROUP BY project_id`,
      params
    );
    rStats.rows.forEach((row) => {
      statsByProject[row.project_id] = {
        total_events: parseInt(row.total_events, 10),
        purchases: parseInt(row.purchases, 10),
        total_value: parseFloat(row.total_value) || 0
      };
    });
  } catch (e) {
    // ignora
  }
  let costByUtm = {};
  try {
    const rCost = await pool.query('SELECT utm_source, utm_medium, utm_campaign, cost FROM campaign_costs');
    rCost.rows.forEach((row) => {
      const key = [row.utm_source, row.utm_medium, row.utm_campaign].join('\0');
      costByUtm[key] = parseFloat(row.cost) || 0;
    });
  } catch (e) {
    // ignora
  }
  let utmData = [];
  try {
    const dateCondUtm = dateFrom ? ' AND created_at >= $1' : '';
    const utmParams = dateFrom ? [dateFrom.toISOString()] : [];
    const rUtm = await pool.query(
      `SELECT COALESCE(context->>'utm_source', '—') AS utm_source,
              COALESCE(context->>'utm_medium', '—') AS utm_medium,
              COALESCE(context->>'utm_campaign', '—') AS utm_campaign,
              COUNT(*) AS purchases, COALESCE(SUM(value), 0) AS total_value
       FROM normalized_events
       WHERE event_name = 'Purchase'${dateCondUtm}
       GROUP BY context->>'utm_source', context->>'utm_medium', context->>'utm_campaign'
       ORDER BY total_value DESC LIMIT 50`,
      utmParams
    );
    utmData = rUtm.rows.map((row) => {
      const purchases = parseInt(row.purchases, 10) || 0;
      const v = parseFloat(row.total_value) || 0;
      const key = [row.utm_source, row.utm_medium, row.utm_campaign].join('\0');
      const cost = costByUtm[key] ?? 0;
      const cpa = cost > 0 && purchases > 0 ? cost / purchases : null;
      const roas = cost > 0 && v > 0 ? v / cost : null;
      return { ...row, cost, cpa, roas };
    });
  } catch (e) {
    // ignora
  }

  const rows = [];
  rows.push('Resumo por projeto');
  rows.push('Projeto;Eventos;Compras;Valor total');
  projects.forEach((p) => {
    const s = statsByProject[p.id] || { total_events: 0, purchases: 0, total_value: 0 };
    const valueStr = s.total_value > 0 ? Number(s.total_value).toFixed(2).replace('.', ',') : '';
    rows.push([csvEscape(p.name), s.total_events, s.purchases, valueStr].join(';'));
  });
  rows.push('');
  rows.push('Por campanha (UTM)');
  rows.push('utm_source;utm_medium;utm_campaign;Compras;Valor;Custo;CPA;ROAS');
  utmData.forEach((row) => {
    const vStr = row.total_value > 0 ? Number(row.total_value).toFixed(2).replace('.', ',') : '';
    const costStr = row.cost > 0 ? Number(row.cost).toFixed(2).replace('.', ',') : '';
    const cpaStr = row.cpa != null ? Number(row.cpa).toFixed(2).replace('.', ',') : '';
    const roasStr = row.roas != null ? Number(row.roas).toFixed(2).replace('.', ',') : '';
    rows.push([csvEscape(row.utm_source), csvEscape(row.utm_medium), csvEscape(row.utm_campaign), row.purchases, vStr, costStr, cpaStr, roasStr].join(';'));
  });
  const csv = '\uFEFF' + rows.join('\r\n');
  const filename = 'resumo-' + (period !== 'all' ? period + '-' : '') + new Date().toISOString().slice(0, 10) + '.csv';
  res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
  res.type('text/csv; charset=utf-8').send(csv);
});

app.post('/api/projects', async (req, res) => {
  if (checkAdmin(req, res)) return;
  if (!pool) {
    return res.status(503).json({ error: 'Banco não configurado' });
  }
  const name = req.body?.name?.trim();
  if (!name) {
    return res.status(400).json({ error: 'Campo "name" é obrigatório' });
  }
  const pixelId = req.body?.pixel_id?.trim() || null;
  const accessToken = req.body?.access_token?.trim() || null;
  const testEventCode = req.body?.test_event_code?.trim() || null;
  const enabledConversions = Array.isArray(req.body?.enabled_conversions) && req.body.enabled_conversions.length
    ? req.body.enabled_conversions
    : ['PageView'];
  const keys = generateApiKeys();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const tenantId = await getOrCreateDefaultTenant(client);
    const projectId = crypto.randomUUID();
    try {
      await client.query(
        `INSERT INTO projects (id, tenant_id, name, api_key_public, api_key_secret, status, enabled_conversions)
         VALUES ($1, $2, $3, $4, $5, 'active', $6)`,
        [projectId, tenantId, name, keys.public, keys.secret, JSON.stringify(enabledConversions)]
      );
    } catch (insErr) {
      if (insErr.message && insErr.message.includes('enabled_conversions')) {
        await client.query(
          `INSERT INTO projects (id, tenant_id, name, api_key_public, api_key_secret, status)
           VALUES ($1, $2, $3, $4, $5, 'active')`,
          [projectId, tenantId, name, keys.public, keys.secret]
        );
      } else throw insErr;
    }
    if (pixelId && accessToken) {
      await client.query(
        `INSERT INTO integrations_meta (project_id, pixel_id, access_token, test_event_code, active)
         VALUES ($1, $2, $3, $4, true)`,
        [projectId, pixelId, accessToken, testEventCode || null]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[tracking-core] Erro ao criar projeto:', err.message);
    return res.status(500).json({ error: 'Erro ao criar projeto' });
  } finally {
    client.release();
  }
  const baseUrl = BASE_URL || `${req.protocol}://${req.get('host')}`;
  res.status(201).json({
    id: projectId,
    name,
    api_key_public: keys.public,
    api_key_secret: keys.secret,
    script_snippet: `<script src="${baseUrl}/sdk/browser-tracker.js"></script>\n<script>\n  (function(){\n    var t = TrackingCore.createTracker({ endpoint: '${baseUrl}/events', apiKey: '${keys.public}' });\n    t.trackPageView();\n  })();\n</script>`,
    webhook_url: `${baseUrl}/webhooks/kiwify?project_key=${encodeURIComponent(keys.secret)}`
  });
});

// Editar projeto (nome, Meta, webhook, conversões)
app.patch('/api/projects/:id', async (req, res) => {
  if (checkAdmin(req, res)) return;
  if (!pool) return res.status(503).json({ error: 'Banco não configurado' });
  const projectId = req.params.id;
  const name = req.body?.name?.trim();
  const webhookOutUrl = req.body?.webhook_out_url;
  const pixelId = req.body?.pixel_id?.trim() || null;
  const accessToken = req.body?.access_token?.trim() || null;
  const testEventCode = req.body?.test_event_code?.trim() || null;
  const enabledConversions = req.body?.enabled_conversions;

  try {
    if (name) {
      const upd = await pool.query(
        'UPDATE projects SET name = $2 WHERE id = $1 AND status = $3 RETURNING id',
        [projectId, name, 'active']
      );
      if (upd.rowCount === 0) {
        return res.status(404).json({ error: 'Projeto não encontrado' });
      }
    }
    if (webhookOutUrl !== undefined) {
      const wUpd = await pool.query(
        'UPDATE projects SET webhook_out_url = $2 WHERE id = $1 AND status = $3 RETURNING id',
        [projectId, (webhookOutUrl && String(webhookOutUrl).trim()) || null, 'active']
      );
      if (wUpd.rowCount === 0 && !name) return res.status(404).json({ error: 'Projeto não encontrado' });
    }
    if (enabledConversions !== undefined && Array.isArray(enabledConversions)) {
      try {
        await pool.query(
          'UPDATE projects SET enabled_conversions = $2 WHERE id = $1 AND status = $3 RETURNING id',
          [projectId, JSON.stringify(enabledConversions), 'active']
        );
      } catch (colErr) {
        if (!colErr.message || !colErr.message.includes('enabled_conversions')) throw colErr;
      }
    }
    if (pixelId !== undefined && accessToken !== undefined) {
      const r = await pool.query(
        'SELECT id FROM integrations_meta WHERE project_id = $1 AND active = true LIMIT 1',
        [projectId]
      );
      if (r.rows[0]) {
        await pool.query(
          'UPDATE integrations_meta SET pixel_id = $2, access_token = $3, test_event_code = $4 WHERE id = $1',
          [r.rows[0].id, pixelId || '', accessToken || '', testEventCode || null]
        );
      } else if (pixelId && accessToken) {
        await pool.query(
          `INSERT INTO integrations_meta (project_id, pixel_id, access_token, test_event_code, active)
           VALUES ($1, $2, $3, $4, true)`,
          [projectId, pixelId, accessToken, testEventCode || null]
        );
      }
    }
    return res.json({ ok: true });
  } catch (err) {
    console.error('[tracking-core] Erro ao editar projeto:', err.message);
    return res.status(500).json({ error: 'Erro ao editar projeto' });
  }
});

// Desativar projeto
app.post('/api/projects/:id/deactivate', async (req, res) => {
  if (checkAdmin(req, res)) return;
  if (!pool) return res.status(503).json({ error: 'Banco não configurado' });
  const projectId = req.params.id;
  try {
    const r = await pool.query(
      "UPDATE projects SET status = 'inactive' WHERE id = $1 RETURNING id",
      [projectId]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: 'Projeto não encontrado' });
    return res.json({ ok: true });
  } catch (err) {
    console.error('[tracking-core] Erro ao desativar projeto:', err.message);
    return res.status(500).json({ error: 'Erro ao desativar projeto' });
  }
});

app.post('/api/projects/:id/activate', async (req, res) => {
  if (checkAdmin(req, res)) return;
  if (!pool) return res.status(503).json({ error: 'Banco não configurado' });
  const projectId = req.params.id;
  try {
    const r = await pool.query(
      "UPDATE projects SET status = 'active' WHERE id = $1 RETURNING id",
      [projectId]
    );
    if (r.rowCount === 0) return res.status(404).json({ error: 'Projeto não encontrado' });
    return res.json({ ok: true });
  } catch (err) {
    console.error('[tracking-core] Erro ao reativar projeto:', err.message);
    return res.status(500).json({ error: 'Erro ao reativar projeto' });
  }
});

// Enviar evento de teste (PageView) para um projeto
app.post('/api/projects/:id/test-event', async (req, res) => {
  if (checkAdmin(req, res)) return;
  if (!pool) return res.status(503).json({ error: 'Banco não configurado' });
  const projectId = req.params.id;
  const baseUrl = BASE_URL || `${req.protocol}://${req.get('host')}`;
  try {
    const r = await pool.query(
      'SELECT api_key_public FROM projects WHERE id = $1 AND status = $2 LIMIT 1',
      [projectId, 'active']
    );
    if (!r.rows[0]) return res.status(404).json({ error: 'Projeto não encontrado ou inativo' });
    const apiKey = r.rows[0].api_key_public;
    const testEvent = {
      event_name: 'PageView',
      event_id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      user: {},
      context: { url: 'https://test/tracking-core' },
      properties: {}
    };
    const ax = await axios.post(`${baseUrl}/events`, testEvent, {
      headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
      timeout: 10000,
      validateStatus: () => true
    });
    if (ax.status >= 400) {
      return res.status(ax.status).json({ error: ax.data?.error || 'Falha ao enviar evento de teste' });
    }
    return res.json({ ok: true, message: 'Evento PageView de teste enviado. Confira em Ver eventos.' });
  } catch (err) {
    console.error('[tracking-core] Erro ao enviar evento de teste:', err.message);
    return res.status(500).json({ error: 'Erro ao enviar evento de teste' });
  }
});

// Últimos eventos do projeto (para o painel)
// Custo manual por campanha (UTM) para CPA/ROAS
app.put('/api/campaign-cost', async (req, res) => {
  if (checkAdmin(req, res)) return;
  if (!pool) return res.status(503).json({ error: 'Banco não configurado' });
  const utmSource = String(req.body?.utm_source ?? '').trim() || '—';
  const utmMedium = String(req.body?.utm_medium ?? '').trim() || '—';
  const utmCampaign = String(req.body?.utm_campaign ?? '').trim() || '—';
  const cost = parseFloat(req.body?.cost);
  if (Number.isNaN(cost) || cost < 0) {
    return res.status(400).json({ error: 'Custo deve ser um número >= 0' });
  }
  try {
    await pool.query(
      `INSERT INTO campaign_costs (utm_source, utm_medium, utm_campaign, cost, updated_at)
       VALUES ($1, $2, $3, $4, now())
       ON CONFLICT (utm_source, utm_medium, utm_campaign)
       DO UPDATE SET cost = $4, updated_at = now()`,
      [utmSource, utmMedium, utmCampaign, cost]
    );
    return res.json({ ok: true });
  } catch (err) {
    console.error('[tracking-core] Erro ao salvar custo:', err.message);
    return res.status(500).json({ error: 'Erro ao salvar custo' });
  }
});

app.get('/api/projects/:id/events', async (req, res) => {
  if (checkAdmin(req, res)) return;
  if (!pool) return res.status(503).json({ error: 'Banco não configurado' });
  const projectId = req.params.id;
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
  try {
    const r = await pool.query(
      `SELECT id, event_name, order_id, value, currency, source, status, created_at
       FROM normalized_events
       WHERE project_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [projectId, limit]
    );
    const proj = await pool.query(
      'SELECT id, name FROM projects WHERE id = $1 LIMIT 1',
      [projectId]
    );
    if (!proj.rows[0]) return res.status(404).json({ error: 'Projeto não encontrado' });
    return res.json({ project: proj.rows[0], events: r.rows });
  } catch (err) {
    console.error('[tracking-core] Erro ao listar eventos:', err.message);
    return res.status(500).json({ error: 'Erro ao listar eventos' });
  }
});

// Exportar eventos de um projeto em CSV
app.get('/painel/events/:projectId/export', async (req, res) => {
  if (!ADMIN_SECRET) return res.status(503).send('Painel desativado.');
  if (!isAdminAuthorized(req)) return res.redirect(302, '/login');
  if (!pool) return res.status(503).send('Banco não configurado.');
  const { projectId } = req.params;
  const period = req.query.period || 'all';
  let dateFrom = null;
  if (period === '1d') dateFrom = new Date(Date.now() - 24 * 60 * 60 * 1000);
  else if (period === '7d') dateFrom = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  else if (period === '30d') dateFrom = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  try {
    const proj = await pool.query(
      'SELECT id, name FROM projects WHERE id = $1 LIMIT 1',
      [projectId]
    );
    if (!proj.rows[0]) return res.status(404).send('Projeto não encontrado.');
    const dateCond = dateFrom ? ' AND created_at >= $2' : '';
    const params = dateFrom ? [projectId, dateFrom.toISOString()] : [projectId];
    const r = await pool.query(
      `SELECT event_name, order_id, value, currency, source, status, created_at
       FROM normalized_events WHERE project_id = $1${dateCond} ORDER BY created_at DESC LIMIT 500`,
      params
    );
    const header = 'Data;Evento;Pedido;Valor;Moeda;Origem;Status';
    const csvRows = r.rows.map((e) =>
      [csvEscape(e.created_at), csvEscape(e.event_name), csvEscape(e.order_id || ''), e.value != null ? e.value : '', csvEscape(e.currency || ''), csvEscape(e.source), csvEscape(e.status)].join(';')
    );
    const csv = '\uFEFF' + [header, ...csvRows].join('\r\n');
    const filename = 'eventos-' + projectId.slice(0, 8) + '-' + (period !== 'all' ? period + '-' : '') + new Date().toISOString().slice(0, 10) + '.csv';
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    res.type('text/csv; charset=utf-8').send(csv);
  } catch (err) {
    console.error('[tracking-core] Erro ao exportar eventos:', err.message);
    return res.status(500).send('Erro ao exportar.');
  }
});

// Página do painel: últimos eventos de um projeto
app.get('/painel/events/:projectId', async (req, res) => {
  if (!ADMIN_SECRET) return res.status(503).send('Painel desativado.');
  if (!isAdminAuthorized(req)) return res.redirect(302, '/login');
  if (!pool) return res.status(503).send('Banco não configurado.');
  const { projectId } = req.params;
  const adminKey = req.query.key || '';
  const period = req.query.period || 'all';
  let dateFrom = null;
  if (period === '1d') dateFrom = new Date(Date.now() - 24 * 60 * 60 * 1000);
  else if (period === '7d') dateFrom = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  else if (period === '30d') dateFrom = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  try {
    const proj = await pool.query(
      'SELECT id, name FROM projects WHERE id = $1 LIMIT 1',
      [projectId]
    );
    if (!proj.rows[0]) return res.status(404).send('Projeto não encontrado.');
    const dateCond = dateFrom ? ' AND created_at >= $2' : '';
    const params = dateFrom ? [projectId, dateFrom.toISOString()] : [projectId];
    const r = await pool.query(
      `SELECT id, event_name, order_id, value, currency, source, status, created_at
       FROM normalized_events WHERE project_id = $1${dateCond} ORDER BY created_at DESC LIMIT 100`,
      params
    );
    const exportCsvUrl = '/painel/events/' + projectId + '/export?' + (period !== 'all' ? 'period=' + period + '&' : '') + (adminKey ? 'key=' + encodeURIComponent(adminKey) : '');
    const rows = r.rows
      .map(
        (e) =>
          `<tr><td>${escapeHtml(e.created_at)}</td><td>${escapeHtml(e.event_name)}</td><td>${escapeHtml(e.order_id || '—')}</td><td>${e.value != null ? e.value : '—'}</td><td>${escapeHtml(e.source)}</td><td>${escapeHtml(e.status)}</td></tr>`
      )
      .join('');
    const periodQuery = period !== 'all' ? '&period=' + period : '';
    const html = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Eventos – ${escapeHtml(proj.rows[0].name)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Exo+2:wght@400;500;600;700&family=Orbitron:wght@500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/public/painel.css">
</head>
<body>
  <div class="events-layout">
    <div class="events-header">
      <h1>Eventos: ${escapeHtml(proj.rows[0].name)}</h1>
      <div class="events-header-actions">
        <select id="eventsPeriodSelect" class="period-select" title="Período">
          <option value="all" ${period === 'all' ? 'selected' : ''}>Todo o período</option>
          <option value="1d" ${period === '1d' ? 'selected' : ''}>Últimas 24h</option>
          <option value="7d" ${period === '7d' ? 'selected' : ''}>Últimos 7 dias</option>
          <option value="30d" ${period === '30d' ? 'selected' : ''}>Últimos 30 dias</option>
        </select>
        <a href="${escapeHtml(exportCsvUrl)}" class="btn btn-sm">Exportar CSV</a>
        <a href="/painel?key=${encodeURIComponent(adminKey)}${periodQuery}" class="btn btn-sm">← Voltar ao painel</a>
      </div>
    </div>
    <div class="table-scroll">
    <table class="events-table">
      <thead><tr><th>Data</th><th>Evento</th><th>Pedido</th><th>Valor</th><th>Origem</th><th>Status</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="6" class="events-empty">Nenhum evento no período.</td></tr>'}</tbody>
    </table>
    </div>
  </div>
  <script>
    document.getElementById('eventsPeriodSelect').addEventListener('change', function() {
      var v = this.value;
      var url = '/painel/events/${escapeHtml(projectId)}?' + (v !== 'all' ? 'period=' + v + '&' : '') + 'key=${encodeURIComponent(adminKey)}';
      window.location.href = url;
    });
  </script>
</body>
</html>`;
    res.type('html').send(html);
  } catch (err) {
    console.error('[tracking-core] Erro painel eventos:', err.message);
    res.status(500).send('Erro ao carregar eventos.');
  }
});

// Webhook Kiwify: ?project_key=API_KEY_SECRET ou header X-Webhook-Secret
app.post(
  '/webhooks/kiwify',
  rateLimit(RATE_LIMIT_WEBHOOK, (req) => `wh:${getClientIp(req)}`),
  async (req, res) => {
  const secret =
    req.query.project_key || req.header('X-Webhook-Secret') || req.header('Authorization')?.replace(/^Bearer\s+/i, '');
  if (!secret) {
    return res.status(401).json({ ok: false, error: 'project_key ou X-Webhook-Secret obrigatório' });
  }
  if (!pool) {
    return res.status(503).json({ ok: false, error: 'Banco não configurado' });
  }

  let projectId = null;
  try {
    const r = await pool.query(
      'SELECT id FROM projects WHERE api_key_secret = $1 AND status = $2 LIMIT 1',
      [secret, 'active']
    );
    projectId = r.rows[0]?.id ?? null;
  } catch (e) {
    return res.status(500).json({ ok: false, error: 'Erro ao validar projeto' });
  }
  if (!projectId) {
    return res.status(401).json({ ok: false, error: 'Projeto não encontrado' });
  }

  const ev = mapGatewayPayloadToEvent(req.body, 'kiwify');
  const receivedAt = new Date().toISOString();
  const client = await pool.connect();
  const fakeReq = { headers: {}, socket: {}, ip: '' };

  try {
    await client.query('BEGIN');

    const rawId = crypto.randomUUID();
    await client.query(
      `INSERT INTO raw_events (id, project_id, source, payload, received_at, status) VALUES ($1, $2, $3, $4, $5, $6)`,
      [rawId, projectId, 'kiwify', JSON.stringify(req.body), receivedAt, 'pending']
    );

    const normalized = buildNormalizedEvent(ev, projectId, 'gateway');
    let normalizedInserted = false;
    try {
      await client.query(
        `INSERT INTO normalized_events (id, project_id, event_name, event_id, order_id, value, currency, user_hashes, context, source, source_priority, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
        [
          normalized.id,
          normalized.project_id,
          normalized.event_name,
          normalized.event_id,
          normalized.order_id,
          normalized.value,
          normalized.currency,
          JSON.stringify(normalized.user_hashes),
          JSON.stringify(normalized.context),
          normalized.source,
          normalized.source_priority,
          normalized.status,
          normalized.created_at
        ]
      );
      normalizedInserted = true;
    } catch (insertErr) {
      if (insertErr.code !== '23505') throw insertErr;
    }

    if (normalizedInserted) {
      const metaResult = await sendToMeta(normalized, fakeReq, projectId);
      if (!metaResult.skipped) {
        const deliveryId = crypto.randomUUID();
        await client.query(
          `INSERT INTO deliveries_meta (id, normalized_event_id, status, attempts, last_error, meta_response, sent_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [
            deliveryId,
            normalized.id,
            metaResult.ok ? 'sent' : 'failed',
            1,
            metaResult.ok ? null : JSON.stringify(metaResult.error),
            metaResult.ok ? JSON.stringify(metaResult.meta) : null,
            metaResult.ok ? new Date().toISOString() : null
          ]
        );
        await client.query(
          `UPDATE normalized_events SET status = $2 WHERE id = $1`,
          [normalized.id, metaResult.ok ? 'sent' : 'failed']
        );
      }
      if (normalized.event_name === 'Purchase') notifyOutgoingWebhook(projectId, normalized);
    }

    await client.query(`UPDATE raw_events SET status = $2 WHERE id = $1`, [rawId, 'processed']);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('[tracking-core] Erro webhook Kiwify:', err.message);
    return res.status(500).json({ ok: false, error: 'Erro ao processar webhook' });
  } finally {
    client.release();
  }

  return res.json({ ok: true });
  }
);

// Middleware de erro (deve ser registrado por último)
app.use((err, req, res, next) => {
  console.error('[tracking-core] Erro não tratado:', err.message || err);
  if (!res.headersSent) {
    res.status(500).send('Erro interno. Tente novamente.');
  }
});

app.listen(PORT, () => {
  console.log(`[tracking-core] API rodando na porta ${PORT}`);
  if (!DATABASE_URL) {
    console.log(
      '[tracking-core] AVISO: DATABASE_URL não configurado. Configure um Postgres para persistir eventos.'
    );
  }
  if (!hasMetaConfig) {
    console.log(
      '[tracking-core] AVISO: META_PIXEL_ID/META_ACCESS_TOKEN não configurados. Eventos não serão enviados ao Meta até configurar o .env.'
    );
  }
});

