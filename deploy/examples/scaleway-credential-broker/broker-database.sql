-- Run as the database administrator outside a transaction, after provisioning
-- the corpus database and devres_reader/devres_writer roles. Replace names as
-- needed and explicitly admit any additional maintenance/backup login.
-- Provision passwords through protected tooling, never process arguments.
CREATE ROLE devres_broker LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE DATABASE devres_broker OWNER devres_broker;
REVOKE CONNECT ON DATABASE devres_broker FROM PUBLIC, devres_reader, devres_writer;
GRANT CONNECT ON DATABASE devres_broker TO devres_broker;

-- Revoking a named grant alone cannot override PostgreSQL's PUBLIC grant.
REVOKE CONNECT ON DATABASE devres FROM PUBLIC, devres_broker;
GRANT CONNECT ON DATABASE devres TO devres_reader, devres_writer;
-- Do not grant membership between broker and corpus roles. Verify denial with
-- the actual workload logins; database owners and superusers bypass isolation.
