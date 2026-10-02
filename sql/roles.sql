-- Recommended privilege separation (defense in depth; NOT a substitute for
-- signatures + anchoring). Run as an administrator after `veridex init`.
--
--   app_user      : your application's role. Writes business tables and calls
--                   record() in the same transaction, so it may INSERT evidence
--                   and update the single log_head row, but never UPDATE/DELETE events.
--   veridex_audit : read-only role for verifiers and auditors.

CREATE ROLE veridex_audit NOLOGIN;

GRANT USAGE ON SCHEMA veridex TO app_user, veridex_audit;

GRANT SELECT, INSERT ON veridex.events, veridex.configurations TO app_user;
GRANT SELECT, INSERT, UPDATE ON veridex.protected_resources TO app_user;
GRANT SELECT, UPDATE ON veridex.log_head TO app_user;
REVOKE DELETE, TRUNCATE ON ALL TABLES IN SCHEMA veridex FROM app_user;

GRANT SELECT ON ALL TABLES IN SCHEMA veridex TO veridex_audit;

-- The append-only triggers created by `veridex init` already reject UPDATE and
-- DELETE on events and configurations for every role except superusers (who can
-- disable triggers). Keep superuser credentials out of the application.
