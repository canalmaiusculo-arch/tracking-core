-- Migration: tabela campaign_costs (custo manual por UTM para CPA/ROAS)
CREATE TABLE IF NOT EXISTS campaign_costs (
  utm_source   TEXT NOT NULL,
  utm_medium   TEXT NOT NULL,
  utm_campaign TEXT NOT NULL,
  cost         NUMERIC(12,2) NOT NULL DEFAULT 0,
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (utm_source, utm_medium, utm_campaign)
);
