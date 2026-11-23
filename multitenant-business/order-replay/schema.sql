-- Apply once in a transaction as the disposable database's migrator.
CREATE SCHEMA cephalon_replay;
REVOKE ALL ON SCHEMA cephalon_replay FROM PUBLIC;

CREATE TABLE cephalon_replay.stock (
    tenant_id text COLLATE "C" NOT NULL,
    sku text NOT NULL,
    available integer NOT NULL CHECK (available >= 0),
    PRIMARY KEY (tenant_id, sku)
);

CREATE TABLE cephalon_replay.orders (
    tenant_id text COLLATE "C" NOT NULL,
    order_id uuid NOT NULL,
    sku text NOT NULL,
    quantity integer NOT NULL CHECK (quantity > 0),
    status text NOT NULL CHECK (status IN ('pending', 'reserved')),
    revision integer NOT NULL CHECK (revision >= 0),
    PRIMARY KEY (tenant_id, order_id),
    FOREIGN KEY (tenant_id, sku) REFERENCES cephalon_replay.stock (tenant_id, sku)
);

CREATE TABLE cephalon_replay.outbox (
    tenant_id text COLLATE "C" NOT NULL,
    event_id uuid NOT NULL,
    order_id uuid NOT NULL,
    sku text NOT NULL,
    quantity integer NOT NULL CHECK (quantity > 0),
    event_type text NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version > 0),
    aggregate_version integer NOT NULL CHECK (aggregate_version >= 0),
    trace_id text NOT NULL CHECK (trace_id ~ '^[0-9a-f]{32}$'),
    published boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id, event_id),
    UNIQUE (tenant_id, event_id, order_id),
    FOREIGN KEY (tenant_id, order_id) REFERENCES cephalon_replay.orders (tenant_id, order_id)
);

CREATE TABLE cephalon_replay.inbox (
    tenant_id text COLLATE "C" NOT NULL,
    event_id uuid NOT NULL,
    order_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, event_id),
    FOREIGN KEY (tenant_id, event_id, order_id) REFERENCES cephalon_replay.outbox (tenant_id, event_id, order_id)
);

INSERT INTO cephalon_replay.stock VALUES ('A', 'fixture-sku', 10), ('B', 'fixture-sku', 20);
INSERT INTO cephalon_replay.orders VALUES
    ('B', '00000000-0000-0000-0000-000000000101', 'fixture-sku', 2, 'pending', 0);

ALTER TABLE cephalon_replay.stock ENABLE ROW LEVEL SECURITY;
ALTER TABLE cephalon_replay.stock FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cephalon_replay.stock TO cephalon_replay_runtime
    USING (tenant_id = NULLIF(current_setting('cephalon_replay.tenant_id', true), ''))
    WITH CHECK (tenant_id = NULLIF(current_setting('cephalon_replay.tenant_id', true), ''));

ALTER TABLE cephalon_replay.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE cephalon_replay.orders FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cephalon_replay.orders TO cephalon_replay_runtime
    USING (tenant_id = NULLIF(current_setting('cephalon_replay.tenant_id', true), ''))
    WITH CHECK (tenant_id = NULLIF(current_setting('cephalon_replay.tenant_id', true), ''));

ALTER TABLE cephalon_replay.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE cephalon_replay.outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cephalon_replay.outbox TO cephalon_replay_runtime
    USING (tenant_id = NULLIF(current_setting('cephalon_replay.tenant_id', true), ''))
    WITH CHECK (tenant_id = NULLIF(current_setting('cephalon_replay.tenant_id', true), ''));

ALTER TABLE cephalon_replay.inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE cephalon_replay.inbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON cephalon_replay.inbox TO cephalon_replay_runtime
    USING (tenant_id = NULLIF(current_setting('cephalon_replay.tenant_id', true), ''))
    WITH CHECK (tenant_id = NULLIF(current_setting('cephalon_replay.tenant_id', true), ''));

GRANT USAGE ON SCHEMA cephalon_replay TO cephalon_replay_runtime;
GRANT SELECT, UPDATE (available) ON cephalon_replay.stock TO cephalon_replay_runtime;
GRANT SELECT, INSERT, UPDATE (status, revision) ON cephalon_replay.orders TO cephalon_replay_runtime;
GRANT SELECT, INSERT, UPDATE (published) ON cephalon_replay.outbox TO cephalon_replay_runtime;
GRANT SELECT, INSERT ON cephalon_replay.inbox TO cephalon_replay_runtime;
