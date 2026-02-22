-- Migration: adiciona coluna webhook_out_url em projects (webhook de saída)
-- Rode no banco já existente: psql $DATABASE_URL -f sql/migrations/001_add_webhook_out.sql

ALTER TABLE projects ADD COLUMN IF NOT EXISTS webhook_out_url TEXT;
