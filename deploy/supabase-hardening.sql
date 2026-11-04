-- Run after the application's first deployment initializes the medicore schema.
-- Keep medicore out of Project Settings > Data API > Exposed schemas.
REVOKE ALL ON SCHEMA medicore FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL TABLES IN SCHEMA medicore FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA medicore REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated;
DO $$ DECLARE t RECORD; BEGIN
  FOR t IN SELECT tablename FROM pg_tables WHERE schemaname='medicore' LOOP
    EXECUTE format('ALTER TABLE medicore.%I ENABLE ROW LEVEL SECURITY', t.tablename);
  END LOOP;
END $$;
-- The server database role must own these tables or have BYPASSRLS.
-- No browser client connects directly to these tables.
