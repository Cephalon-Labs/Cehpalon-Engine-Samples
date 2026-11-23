-- Apply explicitly as the schema owner in a single transaction.
CREATE SCHEMA cephalon_orders;
REVOKE ALL ON SCHEMA cephalon_orders FROM PUBLIC;

CREATE TABLE cephalon_orders.orders (
    tenant_id text COLLATE "C" NOT NULL
        CHECK (tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$'),
    order_id integer NOT NULL CHECK (order_id > 0),
    status text NOT NULL CHECK (status IN ('pending', 'review', 'complete')),
    revision integer NOT NULL CHECK (revision >= 0),
    PRIMARY KEY (tenant_id, order_id)
);

ALTER TABLE cephalon_orders.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE cephalon_orders.orders FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cephalon_orders.orders TO cephalon_orders_runtime
    USING (tenant_id = NULLIF(current_setting('cephalon_orders.tenant_id', true), ''))
    WITH CHECK (tenant_id = NULLIF(current_setting('cephalon_orders.tenant_id', true), ''));

GRANT USAGE ON SCHEMA cephalon_orders TO cephalon_orders_runtime;
GRANT SELECT, UPDATE (status, revision) ON cephalon_orders.orders TO cephalon_orders_runtime;
