-- Seed inicial: um tenant, um projeto e (opcional) integração Meta
-- Rode depois do schema.sql. Troque api_key_* e pixel/access_token pelos seus.

INSERT INTO tenants (id, name, status)
VALUES (
  'a0000000-0000-0000-0000-000000000001',
  'Meu Cliente',
  'active'
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO projects (id, tenant_id, name, api_key_public, api_key_secret, status)
VALUES (
  'b0000000-0000-0000-0000-000000000001',
  'a0000000-0000-0000-0000-000000000001',
  'Meu Projeto',
  'pk_live_xxxxxxxxxxxxxxxx',
  'sk_live_xxxxxxxxxxxxxxxx',
  'active'
)
ON CONFLICT (id) DO NOTHING;

-- Opcional: descomente e preencha com seu Pixel e token para este projeto
-- INSERT INTO integrations_meta (project_id, pixel_id, access_token, test_event_code, active)
-- VALUES (
--   'b0000000-0000-0000-0000-000000000001',
--   'SEU_PIXEL_ID',
--   'SEU_ACCESS_TOKEN',
--   NULL,
--   true
-- );
