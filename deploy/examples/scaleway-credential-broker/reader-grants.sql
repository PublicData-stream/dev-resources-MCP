-- Run as the corpus database owner while connected to the corpus database.
-- Provision the password through protected operator tooling, never CLI arguments.
-- This role must not own objects or inherit a write-capable role.
CREATE ROLE devres_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE devres TO devres_reader;
GRANT USAGE ON SCHEMA public TO devres_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO devres_reader;
ALTER DEFAULT PRIVILEGES FOR ROLE devres_writer IN SCHEMA public
  GRANT SELECT ON TABLES TO devres_reader;
ALTER ROLE devres_reader SET default_transaction_read_only = on;
-- Use a separately provisioned owner/login for the dedicated broker database.
-- The broker database must never be included in the public corpus archive dump.
