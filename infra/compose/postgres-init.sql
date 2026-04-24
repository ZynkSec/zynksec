-- Zynksec Postgres bootstrap.
--
-- The postgres:16-alpine image creates POSTGRES_DB automatically on
-- first start; this script only adds the extensions Zynksec relies on
-- (pgcrypto for UUID and digest helpers the Week-2 models will use).
-- It is mounted read-only into /docker-entrypoint-initdb.d/ and runs
-- once, on an empty data volume.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
