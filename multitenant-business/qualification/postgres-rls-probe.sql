-- Run via psql -X against a disposable PostgreSQL 18.6 fixture database
-- as the fixture administrator. The transaction rolls back fixture DDL by default.
-- The disposable runtime-role mode keeps it only until the container is removed.
\set ON_ERROR_STOP on
BEGIN;

CREATE ROLE cephalon_probe_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE cephalon_probe_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE SCHEMA cephalon_rls_probe AUTHORIZATION cephalon_probe_owner;

SET LOCAL ROLE cephalon_probe_owner;
CREATE TABLE cephalon_rls_probe.orders (
    tenant_id uuid NOT NULL,
    order_id integer NOT NULL,
    PRIMARY KEY (tenant_id, order_id)
);
INSERT INTO cephalon_rls_probe.orders VALUES
    ('00000000-0000-0000-0000-000000000001', 1),
    ('00000000-0000-0000-0000-000000000002', 1);

ALTER TABLE cephalon_rls_probe.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE cephalon_rls_probe.orders FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cephalon_rls_probe.orders
    USING (tenant_id = NULLIF(current_setting('cephalon_probe.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('cephalon_probe.tenant_id', true), '')::uuid);
GRANT USAGE ON SCHEMA cephalon_rls_probe TO cephalon_probe_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON cephalon_rls_probe.orders TO cephalon_probe_runtime;
RESET ROLE;
SET LOCAL ROLE cephalon_probe_runtime;

DO $$
BEGIN
    IF EXISTS (SELECT FROM cephalon_rls_probe.orders) THEN
        RAISE EXCEPTION 'Missing tenant context exposed rows';
    END IF;
END
$$;

SAVEPOINT tenant_a;
SELECT set_config('cephalon_probe.tenant_id', '00000000-0000-0000-0000-000000000001', true);
DO $$
DECLARE
    changed integer;
BEGIN
    IF (SELECT array_agg(tenant_id) FROM cephalon_rls_probe.orders)
        IS DISTINCT FROM ARRAY['00000000-0000-0000-0000-000000000001'::uuid] THEN
        RAISE EXCEPTION 'Tenant A aggregate did not contain exactly its own row';
    END IF;

    UPDATE cephalon_rls_probe.orders SET order_id = 2
        WHERE tenant_id = '00000000-0000-0000-0000-000000000002';
    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed <> 0 THEN
        RAISE EXCEPTION 'Cross-tenant update modified rows';
    END IF;

    BEGIN
        INSERT INTO cephalon_rls_probe.orders VALUES ('00000000-0000-0000-0000-000000000002', 2);
        RAISE EXCEPTION 'Cross-tenant insert succeeded';
    EXCEPTION WHEN insufficient_privilege THEN
        NULL;
    END;

    INSERT INTO cephalon_rls_probe.orders VALUES ('00000000-0000-0000-0000-000000000001', 2);
    IF (SELECT count(*) FROM cephalon_rls_probe.orders) <> 2 THEN
        RAISE EXCEPTION 'Tenant A could not see its own insert';
    END IF;
END
$$;
ROLLBACK TO SAVEPOINT tenant_a;

DO $$
BEGIN
    IF EXISTS (SELECT FROM cephalon_rls_probe.orders) THEN
        RAISE EXCEPTION 'Tenant context survived savepoint rollback';
    END IF;
END
$$;

SELECT set_config('cephalon_probe.tenant_id', '00000000-0000-0000-0000-000000000002', true);
DO $$
BEGIN
    IF (SELECT array_agg(tenant_id) FROM cephalon_rls_probe.orders)
        IS DISTINCT FROM ARRAY['00000000-0000-0000-0000-000000000002'::uuid] THEN
        RAISE EXCEPTION 'Tenant B aggregate did not contain exactly its own row';
    END IF;
END
$$;

SELECT set_config('cephalon_probe.tenant_id', '00000000-0000-0000-0000-000000000001', true);
DO $$
BEGIN
    IF (SELECT array_agg(order_id) FROM cephalon_rls_probe.orders) IS DISTINCT FROM ARRAY[1] THEN
        RAISE EXCEPTION 'Tenant A insert survived savepoint rollback';
    END IF;
END
$$;

\if :{?keep_runtime_fixture}
\else
    \set keep_runtime_fixture false
\endif
\if :keep_runtime_fixture
    \set runtime_password
    \getenv runtime_password CEPHALON_PROBE_RUNTIME_PASSWORD
    SELECT LENGTH(:'runtime_password') > 0 AS has_runtime_password \gset
    \if :has_runtime_password
        RESET ROLE;
        ALTER ROLE cephalon_probe_runtime LOGIN PASSWORD :'runtime_password';
        COMMIT;
    \else
        DO $$ BEGIN RAISE EXCEPTION 'Runtime fixture password is required'; END $$;
    \endif
\else
    ROLLBACK;
\endif
