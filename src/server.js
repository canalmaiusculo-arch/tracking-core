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

app.get('/painel', async (req, res) => {
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
      const v = parseFloat(row.total_value) || 0;
      const valueStr = v > 0 ? 'R$ ' + Number(v).toFixed(2).replace('.', ',') : '—';
      return `<tr><td>${escapeHtml(row.utm_source)}</td><td>${escapeHtml(row.utm_medium)}</td><td>${escapeHtml(row.utm_campaign)}</td><td>${row.purchases}</td><td>${valueStr}</td></tr>`;
    });
  } catch (e) {
    // ignora
  }
  const utmRowsHtml = utmRows.join('');

  const summaryRows = projects
    .map((p) => {
      const s = statsByProject[p.id] || { total_events: 0, purchases: 0, total_value: 0 };
      const valueStr = s.total_value > 0 ? 'R$ ' + Number(s.total_value).toFixed(2).replace('.', ',') : '—';
      return `<tr><td>${escapeHtml(p.name)}</td><td>${s.total_events}</td><td>${s.purchases}</td><td>${valueStr}</td></tr>`;
    })
    .join('');
  const periodQuery = period !== 'all' ? `?period=${period}` : '';
  const summaryHtml =
    `<div class="section-header"><h2 class="section-title" id="resumo">Resumo</h2>
    <select id="periodSelect" class="period-select" title="Período">
      <option value="all" ${period === 'all' ? 'selected' : ''}>Todo o período</option>
      <option value="1d" ${period === '1d' ? 'selected' : ''}>Últimas 24h</option>
      <option value="7d" ${period === '7d' ? 'selected' : ''}>Últimos 7 dias</option>
      <option value="30d" ${period === '30d' ? 'selected' : ''}>Últimos 30 dias</option>
    </select></div>
    <table class="dashboard-table">
      <thead><tr><th>Projeto</th><th>Eventos</th><th>Compras</th><th>Valor total</th></tr></thead>
      <tbody>${summaryRows || '<tr><td colspan="4" class="events-empty">Nenhum projeto com eventos no período.</td></tr>'}</tbody>
    </table>
    ${utmRowsHtml ? `<h3 class="section-subtitle">Por campanha (UTM)</h3>
    <table class="dashboard-table">
      <thead><tr><th>utm_source</th><th>utm_medium</th><th>utm_campaign</th><th>Compras</th><th>Valor</th></tr></thead>
      <tbody>${utmRowsHtml}</tbody>
    </table>` : ''}`;

  const projectsHtml = projects
    .map(
      (p) => `
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
      <span class="label">Chave pública</span>
      <p style="margin:0 0 1rem 0;"><code>${escapeHtml(p.api_key_public)}</code></p>
      <span class="label">Script para o cabeçalho</span>
      <div class="copy-wrap">
        <pre class="snippet">${escapeHtml(p.script_snippet)}</pre>
        <button type="button" class="btn btn-sm" data-copy="${escapeHtml(p.script_snippet)}">Copiar script</button>
      </div>
      <span class="label">URL webhook Kiwify</span>
      <div class="copy-wrap">
        <pre class="snippet url">${escapeHtml(p.webhook_url)}</pre>
        <button type="button" class="btn btn-sm" data-copy="${escapeHtml(p.webhook_url)}">Copiar URL</button>
      </div>
    </div>`
    )
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

  const html = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Painel – Tracking Core</title>
  <link rel="stylesheet" href="/public/painel.css">
</head>
<body>
  <div class="dashboard-wrap">
    <aside class="dashboard-sidebar">
      <div class="sidebar-logo">Tracking Core</div>
      <nav class="sidebar-nav">
        <a href="#resumo" class="sidebar-link">Resumo</a>
        <a href="#projetos" class="sidebar-link">Projetos</a>
      </nav>
      <a href="/logout" class="sidebar-link sidebar-logout">Sair</a>
    </aside>
    <main class="dashboard-main">
      <header class="dashboard-header">
        <h1 class="dashboard-title">Dashboard</h1>
        <span class="dashboard-user">Admin</span>
      </header>
      <div class="dashboard-content">
        ${summaryHtml}

        <h2 class="section-title" id="projetos">Projetos</h2>
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
    </div>
      </div>
    </main>
  </div>

  <script>
    var adminKey = ${JSON.stringify(adminKey)};
    var periodQuery = ${JSON.stringify(periodQuery)};
    var sel = document.getElementById('periodSelect');
    if (sel) sel.addEventListener('change', function() {
      var v = this.value;
      var q = v !== 'all' ? '?period=' + v : '';
      if (adminKey) q += (q ? '&' : '?') + 'key=' + encodeURIComponent(adminKey);
      window.location.href = '/painel' + q;
    });
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
      var fd = new FormData(this);
      var payload = { name: fd.get('name') };
      if (fd.get('pixel_id')) payload.pixel_id = fd.get('pixel_id');
      if (fd.get('access_token')) payload.access_token = fd.get('access_token');
      if (fd.get('test_event_code')) payload.test_event_code = fd.get('test_event_code');
      var apiHeaders = { 'Content-Type': 'application/json' };
    if (adminKey) apiHeaders['X-Admin-Key'] = adminKey;
    fetch('/api/projects', {
        method: 'POST',
        headers: apiHeaders,
        credentials: 'same-origin',
        body: JSON.stringify(payload)
      }).then(function(r) {
        if (r.ok) return r.json();
        throw new Error(r.status === 401 ? 'Chave de admin inválida' : 'Erro ao criar projeto');
      }).then(function() { window.location.reload(); })
        .catch(function(err) { alert(err.message); });
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
      var wout = document.getElementById('editWebhookOutUrl').value.trim();
      payload.webhook_out_url = wout;
      var patchHeaders = { 'Content-Type': 'application/json' };
      if (adminKey) patchHeaders['X-Admin-Key'] = adminKey;
      fetch('/api/projects/' + encodeURIComponent(id), {
        method: 'PATCH',
        headers: patchHeaders,
        credentials: 'same-origin',
        body: JSON.stringify(payload)
      }).then(function(r) {
        if (r.ok) { modalEdit.classList.remove('show'); window.location.reload(); return; }
        return r.json().then(function(d) { throw new Error(d.error || 'Erro ao salvar'); });
      }).catch(function(err) { alert(err.message); });
    });

    document.querySelectorAll('.btn-deactivate').forEach(function(btn) {
      btn.addEventListener('click', function() {
        if (!confirm('Desativar o projeto \"' + (btn.getAttribute('data-name') || '') + '\"? O script e o webhook pararão de aceitar eventos.')) return;
        var id = btn.getAttribute('data-id');
        var logoutHeaders = {};
      if (adminKey) logoutHeaders['X-Admin-Key'] = adminKey;
      fetch('/api/projects/' + encodeURIComponent(id) + '/deactivate', {
          method: 'POST',
          headers: logoutHeaders,
          credentials: 'same-origin'
        }).then(function(r) {
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
        fetch('/api/projects/' + encodeURIComponent(id) + '/activate', {
          method: 'POST',
          headers: headers,
          credentials: 'same-origin'
        }).then(function(r) {
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
        fetch('/api/projects/' + encodeURIComponent(id) + '/test-event', {
          method: 'POST',
          headers: headers,
          credentials: 'same-origin'
        }).then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); }).then(function(o) {
          btn.disabled = false;
          var t = document.getElementById('toast');
          if (o.ok) { t.textContent = 'Evento de teste enviado!'; t.style.display = 'block'; setTimeout(function() { t.style.display = 'none'; }, 3000); }
          else { alert(o.data.error || 'Erro ao enviar evento'); }
        }).catch(function(err) { btn.disabled = false; alert(err.message); });
      });
    });
  </script>
</body>
</html>`;
  res.type('html').send(html);
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
  const keys = generateApiKeys();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const tenantId = await getOrCreateDefaultTenant(client);
    const projectId = crypto.randomUUID();
    await client.query(
      `INSERT INTO projects (id, tenant_id, name, api_key_public, api_key_secret, status)
       VALUES ($1, $2, $3, $4, $5, 'active')`,
      [projectId, tenantId, name, keys.public, keys.secret]
    );
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

// Editar projeto (nome e/ou Meta)
app.patch('/api/projects/:id', async (req, res) => {
  if (checkAdmin(req, res)) return;
  if (!pool) return res.status(503).json({ error: 'Banco não configurado' });
  const projectId = req.params.id;
  const name = req.body?.name?.trim();
  const webhookOutUrl = req.body?.webhook_out_url;
  const pixelId = req.body?.pixel_id?.trim() || null;
  const accessToken = req.body?.access_token?.trim() || null;
  const testEventCode = req.body?.test_event_code?.trim() || null;

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

// Página do painel: últimos eventos de um projeto
app.get('/painel/events/:projectId', async (req, res) => {
  if (!ADMIN_SECRET) return res.status(503).send('Painel desativado.');
  if (!isAdminAuthorized(req)) return res.redirect(302, '/login');
  if (!pool) return res.status(503).send('Banco não configurado.');
  const { projectId } = req.params;
  const adminKey = req.query.key;
  try {
    const proj = await pool.query(
      'SELECT id, name FROM projects WHERE id = $1 LIMIT 1',
      [projectId]
    );
    if (!proj.rows[0]) return res.status(404).send('Projeto não encontrado.');
    const r = await pool.query(
      `SELECT id, event_name, order_id, value, currency, source, status, created_at
       FROM normalized_events WHERE project_id = $1 ORDER BY created_at DESC LIMIT 100`,
      [projectId]
    );
    const rows = r.rows
      .map(
        (e) =>
          `<tr><td>${escapeHtml(e.created_at)}</td><td>${escapeHtml(e.event_name)}</td><td>${escapeHtml(e.order_id || '—')}</td><td>${e.value != null ? e.value : '—'}</td><td>${escapeHtml(e.source)}</td><td>${escapeHtml(e.status)}</td></tr>`
      )
      .join('');
    const html = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Eventos – ${escapeHtml(proj.rows[0].name)}</title>
  <link rel="stylesheet" href="/public/painel.css">
</head>
<body>
  <div class="events-layout">
    <div class="events-header">
      <h1>Eventos: ${escapeHtml(proj.rows[0].name)}</h1>
      <a href="/painel?key=${encodeURIComponent(adminKey || '')}" class="btn btn-sm">← Voltar ao painel</a>
    </div>
    <table class="events-table">
      <thead><tr><th>Data</th><th>Evento</th><th>Pedido</th><th>Valor</th><th>Origem</th><th>Status</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="6" class="events-empty">Nenhum evento ainda.</td></tr>'}</tbody>
    </table>
  </div>
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

