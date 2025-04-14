DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'history' AND typnamespace = (SELECT oid FROM pg_namespace WHERE nspname = current_schema())) THEN
        CREATE TYPE history AS (
            id text,
            event text,
            severity text,
            status text,
            value text,
            text text,
            type text,
            update_time timestamp without time zone,
            "user" text,
            timeout integer
        );
    ELSE
        BEGIN
            ALTER TYPE history ADD ATTRIBUTE "user" text CASCADE;
        EXCEPTION
            WHEN duplicate_column THEN RAISE NOTICE 'column "user" already exists in history type.';
        END;
        BEGIN
            ALTER TYPE history ADD ATTRIBUTE timeout integer CASCADE;
        EXCEPTION
            WHEN duplicate_column THEN RAISE NOTICE 'column "timeout" already exists in history type.';
        END;
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS issues (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    summary TEXT NOT NULL,
    severity TEXT,
    host_critical TEXT,
    duty_admin TEXT,
    description TEXT,
    status TEXT,
    status_duration INTERVAL,
    create_time TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_alert_time TIMESTAMP WITHOUT TIME ZONE,
    resolve_time TIMESTAMP WITHOUT TIME ZONE,
    pattern_id INTEGER,
    inc_key TEXT,
    slack_link TEXT,
    disaster_link TEXT,
    escalation_group TEXT,
    alerts TEXT[],
    hosts TEXT[],
    project_groups TEXT[],
    info_systems TEXT[],
    attributes JSONB,
    master_incident UUID,
    issue_history history[]
);

CREATE TABLE IF NOT EXISTS alerts (
    id text PRIMARY KEY,
    resource text NOT NULL,
    event text NOT NULL,
    environment text,
    severity text,
    correlate text[],
    status text,
    service text[],
    "group" text,
    value text,
    text text,
    tags text[],
    attributes jsonb,
    origin text,
    type text,
    create_time timestamp without time zone,
    timeout integer,
    raw_data text,
    customer text,
    duplicate_count integer,
    repeat boolean,
    previous_severity text,
    trend_indication text,
    receive_time timestamp without time zone,
    last_receive_id text,
    last_receive_time timestamp without time zone,
    history history[],
    issue_id UUID REFERENCES issues(id)
);

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS update_time timestamp without time zone;

CREATE TABLE IF NOT EXISTS patterns (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    sql_rule TEXT NOT NULL,
    priority INTEGER NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    create_time timestamp without time zone NOT NULL,
    update_time timestamp without time zone
);

INSERT INTO patterns (id, name, sql_rule, priority, is_active, create_time, update_time)
SELECT *
FROM (
         VALUES
             (1, 'Physical Host', '%(tags.Hardware)s = ANY(tags)', 1, TRUE, NOW(), NOW()),
             (2, 'cosinus name & host', 'text LIKE %(text)s AND event = %(event)s', 2, FALSE, NOW(), NOW()),
             (3, 'Hostname', 'event = %(event)s', 3, TRUE, NOW(), NOW()),
             (4, 'ProjectGroup/InfoSystem', '%(tags.ProjectGroup)s = ANY(tags) AND %(tags.InfoSystem)s = ANY(tags)', 4, TRUE, NOW(), NOW())
     ) AS new_records (id, name, sql_rule, priority, is_active, create_time, update_time)
WHERE NOT EXISTS (SELECT 1 FROM patterns);

SELECT setval('patterns_id_seq', (SELECT MAX(id) FROM patterns));

CREATE TABLE IF NOT EXISTS pattern_history (
   id SERIAL PRIMARY KEY,
   pattern_name TEXT NOT NULL,
   pattern_id INTEGER NOT NULL,
   incident_id UUID NOT NULL,
   alert_id UUID NOT NULL,
   create_time TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alert_move_history (
   id SERIAL PRIMARY KEY,
   incident_id UUID NOT NULL,
   attributes_updated JSONB,
   user_name TEXT NOT NULL,
   create_time TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS notes (
    id text PRIMARY KEY,
    text text,
    "user" text,
    attributes jsonb,
    type text NOT NULL,
    create_time timestamp without time zone NOT NULL,
    update_time timestamp without time zone,
    alert text,
    customer text
);


CREATE TABLE IF NOT EXISTS blackouts (
    id text PRIMARY KEY,
    priority integer NOT NULL,
    environment text NOT NULL,
    service text[],
    resource text,
    event text,
    "group" text,
    tags text[],
    customer text,
    start_time timestamp without time zone NOT NULL,
    end_time timestamp without time zone NOT NULL,
    duration integer
);

ALTER TABLE blackouts
ADD COLUMN IF NOT EXISTS "user" text,
ADD COLUMN IF NOT EXISTS create_time timestamp without time zone,
ADD COLUMN IF NOT EXISTS text text,
ADD COLUMN IF NOT EXISTS origin text;


CREATE TABLE IF NOT EXISTS customers (
    id text PRIMARY KEY,
    match text NOT NULL,
    customer text
);

ALTER TABLE customers DROP CONSTRAINT IF EXISTS customers_match_key;


CREATE TABLE IF NOT EXISTS heartbeats (
    id text PRIMARY KEY,
    origin text NOT NULL,
    tags text[],
    type text,
    create_time timestamp without time zone,
    timeout integer,
    receive_time timestamp without time zone,
    customer text
);

ALTER TABLE heartbeats ADD COLUMN IF NOT EXISTS attributes jsonb;


CREATE TABLE IF NOT EXISTS keys (
    id text PRIMARY KEY,
    key text UNIQUE NOT NULL,
    "user" text NOT NULL,
    scopes text[],
    text text,
    expire_time timestamp without time zone,
    count integer,
    last_used_time timestamp without time zone,
    customer text
);


CREATE TABLE IF NOT EXISTS metrics (
    "group" text NOT NULL,
    name text NOT NULL,
    title text,
    description text,
    value integer,
    count integer,
    total_time integer,
    type text NOT NULL,
    CONSTRAINT metrics_pkey PRIMARY KEY ("group", name, type)
);
ALTER TABLE metrics ALTER COLUMN total_time TYPE BIGINT;
ALTER TABLE metrics ALTER COLUMN count TYPE BIGINT;


CREATE TABLE IF NOT EXISTS perms (
    id text PRIMARY KEY,
    match text UNIQUE NOT NULL,
    scopes text[]
);


CREATE TABLE IF NOT EXISTS users (
    id text PRIMARY KEY,
    name text,
    email text UNIQUE,
    password text NOT NULL,
    status text,
    roles text[],
    attributes jsonb,
    create_time timestamp without time zone NOT NULL,
    last_login timestamp without time zone,
    text text,
    update_time timestamp without time zone,
    email_verified boolean,
    hash text
);
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;

DO $$
BEGIN
    ALTER TABLE users ADD COLUMN login text UNIQUE;
    UPDATE users SET login = email;
    ALTER TABLE users ALTER COLUMN login SET NOT NULL;
EXCEPTION
    WHEN duplicate_column THEN RAISE NOTICE 'column "login" already exists in users.';
END$$;

CREATE TABLE IF NOT EXISTS groups (
    id text PRIMARY KEY,
    name text UNIQUE NOT NULL,
    users text[],
    text text,
    tags text[],
    attributes jsonb,
    update_time timestamp without time zone
);


CREATE INDEX IF NOT EXISTS env_res_evt_cust_key ON alerts USING btree (environment, resource, event, (COALESCE(customer, ''::text)));


CREATE UNIQUE INDEX IF NOT EXISTS org_cust_key ON heartbeats USING btree (origin, (COALESCE(customer, ''::text)));

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS issue_id UUID REFERENCES issues(id);
