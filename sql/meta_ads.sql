-- Conexão Meta Ads (Marketing API) para listar campanhas e gastos
-- Uma conexão por tenant (conta de anúncios + token OAuth)

CREATE TABLE IF NOT EXISTS meta_ads_connections (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  ad_account_id    TEXT NOT NULL,   -- ex: act_123456789
  ad_account_name  TEXT,
  access_token     TEXT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(tenant_id)
);

COMMENT ON TABLE meta_ads_connections IS 'Token OAuth da Meta Marketing API para ler campanhas e gastos por tenant';
