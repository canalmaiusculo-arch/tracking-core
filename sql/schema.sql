-- Schema inicial para tracking-core (Postgres)

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Clientes (white label)
CREATE TABLE IF NOT EXISTS tenants (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name       TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'active', -- active | suspended
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Projetos (funis / sites) de cada cliente
CREATE TABLE IF NOT EXISTS projects (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id),
  name            TEXT NOT NULL,
  api_key_public  TEXT NOT NULL UNIQUE,
  api_key_secret  TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'active',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Integração com Meta por projeto
CREATE TABLE IF NOT EXISTS integrations_meta (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id      UUID NOT NULL REFERENCES projects(id),
  pixel_id        TEXT NOT NULL,
  access_token    TEXT NOT NULL,
  test_event_code TEXT,
  active          BOOLEAN NOT NULL DEFAULT TRUE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Eventos crus (de SDK ou gateways)
CREATE TABLE IF NOT EXISTS raw_events (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id   UUID REFERENCES projects(id),
  source       TEXT NOT NULL, -- sdk | kiwify | perfectpay | ticto | ...
  payload      JSONB NOT NULL,
  received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  status       TEXT NOT NULL DEFAULT 'pending' -- pending | processed | error
);

-- Eventos normalizados (fonte única da verdade interna)
CREATE TABLE IF NOT EXISTS normalized_events (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id       UUID NOT NULL REFERENCES projects(id),
  event_name       TEXT NOT NULL, -- Purchase | Lead | PageView | ...
  event_id         TEXT,
  order_id         TEXT,
  value            NUMERIC(12,2),
  currency         TEXT,
  user_hashes      JSONB,
  context          JSONB,
  source           TEXT NOT NULL, -- sdk | gateway
  source_priority  INT NOT NULL,  -- gateway > sdk (ex.: 2 > 1)
  status           TEXT NOT NULL DEFAULT 'pending_meta', -- pending_meta | sent | failed
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(project_id, order_id, event_name)
);

-- Log de entregas à Meta
CREATE TABLE IF NOT EXISTS deliveries_meta (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  normalized_event_id UUID NOT NULL REFERENCES normalized_events(id),
  status              TEXT NOT NULL, -- sent | failed
  attempts            INT NOT NULL DEFAULT 1,
  last_error          TEXT,
  meta_response       JSONB,
  sent_at             TIMESTAMPTZ
);

