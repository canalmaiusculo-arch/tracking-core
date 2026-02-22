-- Migration: conversões habilitadas por projeto (para gerar códigos no painel)
ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS enabled_conversions JSONB DEFAULT '["PageView"]'::jsonb;

COMMENT ON COLUMN projects.enabled_conversions IS 'Lista de conversões habilitadas: PageView, ViewContent, AddToCart, InitiateCheckout, Purchase, Lead, Contact, Scroll';
