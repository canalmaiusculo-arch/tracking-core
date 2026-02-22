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
app.use('/sdk', express.static(path.join(__dirname, '../sdk')));

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

// Rota /health para checagem simples
app.get('/health', (req, res) => {
  res.json({ ok: true, status: 'healthy', time: new Date().toISOString() });
});

// Rota /events (equivalente evoluída do MVP)
app.post('/events', async (req, res) => {
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
});

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

// Webhook Kiwify: ?project_key=API_KEY_SECRET ou header X-Webhook-Secret
app.post('/webhooks/kiwify', async (req, res) => {
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

