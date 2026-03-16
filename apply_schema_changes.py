import asyncio
from sqlalchemy import text
from app.database.session import async_engine

async def main():
    async with async_engine.begin() as conn:
        # add columns if missing
        # alter scan_results table one command at a time
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS structural_score integer DEFAULT 0"))
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS vt_score integer DEFAULT 0"))
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS ioc_score integer DEFAULT 0"))
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS risk_score integer DEFAULT 0"))
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS signals_json jsonb DEFAULT '{}'::jsonb"))
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS vt_raw_json jsonb DEFAULT '{}'::jsonb"))
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS summary text DEFAULT ''"))
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS feed_intel_score integer DEFAULT 0"))
        await conn.execute(text("ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS historical_score integer DEFAULT 0"))
        await conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS feed_intel_score integer DEFAULT 0"))
        await conn.execute(text("ALTER TABLE scans ADD COLUMN IF NOT EXISTS historical_score integer DEFAULT 0"))

        # Week 5 graph intelligence schema
        await conn.execute(text("""
        DO $$
        BEGIN
            IF to_regclass('public.threat_actors') IS NULL AND to_regclass('public.threat_actor') IS NOT NULL THEN
                ALTER TABLE threat_actor RENAME TO threat_actors;
            END IF;
        END $$;
        """))

        await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS threat_actors (
            id serial PRIMARY KEY,
            name varchar NOT NULL,
            description text,
            origin varchar,
            aliases jsonb DEFAULT '[]'::jsonb,
            first_seen timestamp without time zone,
            last_seen timestamp without time zone,
            created_at timestamp without time zone DEFAULT now()
        )
        """))
        await conn.execute(text("ALTER TABLE threat_actors ADD COLUMN IF NOT EXISTS description text"))
        await conn.execute(text("ALTER TABLE threat_actors ADD COLUMN IF NOT EXISTS origin varchar"))
        await conn.execute(text("ALTER TABLE threat_actors ADD COLUMN IF NOT EXISTS aliases jsonb DEFAULT '[]'::jsonb"))
        await conn.execute(text("ALTER TABLE threat_actors ADD COLUMN IF NOT EXISTS first_seen timestamp without time zone"))
        await conn.execute(text("ALTER TABLE threat_actors ADD COLUMN IF NOT EXISTS last_seen timestamp without time zone"))
        await conn.execute(text("ALTER TABLE threat_actors ADD COLUMN IF NOT EXISTS created_at timestamp without time zone DEFAULT now()"))
        await conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_threat_actors_name ON threat_actors(name)"))

        await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS malware_families (
            id serial PRIMARY KEY,
            name varchar NOT NULL,
            family_type varchar,
            description text,
            aliases jsonb DEFAULT '[]'::jsonb,
            created_at timestamp without time zone DEFAULT now()
        )
        """))
        await conn.execute(text("ALTER TABLE malware_families ADD COLUMN IF NOT EXISTS family_type varchar"))
        await conn.execute(text("ALTER TABLE malware_families ADD COLUMN IF NOT EXISTS description text"))
        await conn.execute(text("ALTER TABLE malware_families ADD COLUMN IF NOT EXISTS aliases jsonb DEFAULT '[]'::jsonb"))
        await conn.execute(text("ALTER TABLE malware_families ADD COLUMN IF NOT EXISTS created_at timestamp without time zone DEFAULT now()"))
        await conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_malware_families_name ON malware_families(name)"))

        await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS campaigns (
            id serial PRIMARY KEY,
            name varchar NOT NULL,
            description text,
            threat_actor_id integer REFERENCES threat_actors(id),
            first_seen timestamp without time zone,
            last_seen timestamp without time zone,
            created_at timestamp without time zone DEFAULT now()
        )
        """))
        await conn.execute(text("ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS description text"))
        await conn.execute(text("ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS threat_actor_id integer REFERENCES threat_actors(id)"))
        await conn.execute(text("ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS first_seen timestamp without time zone"))
        await conn.execute(text("ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS last_seen timestamp without time zone"))
        await conn.execute(text("ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS created_at timestamp without time zone DEFAULT now()"))
        await conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_campaigns_name ON campaigns(name)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_campaigns_threat_actor_id ON campaigns(threat_actor_id)"))

        await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS ioc_relationships (
            id serial PRIMARY KEY,
            ioc_id integer NOT NULL REFERENCES ioc(id),
            relationship_type varchar NOT NULL,
            related_entity_type varchar NOT NULL,
            related_entity_id integer NOT NULL,
            threat_actor_id integer REFERENCES threat_actors(id),
            malware_family_id integer REFERENCES malware_families(id),
            campaign_id integer REFERENCES campaigns(id),
            source varchar,
            confidence integer DEFAULT 50,
            created_at timestamp without time zone DEFAULT now()
        )
        """))
        await conn.execute(text("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_relationship
        ON ioc_relationships(ioc_id, relationship_type, related_entity_type, related_entity_id)
        """))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ioc_relationships_ioc_id ON ioc_relationships(ioc_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ioc_relationships_threat_actor_id ON ioc_relationships(threat_actor_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ioc_relationships_malware_family_id ON ioc_relationships(malware_family_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ioc_relationships_campaign_id ON ioc_relationships(campaign_id)"))

        # IOC graph edges (IOC -> IOC) for relationship investigations.
        await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS ioc_graph_relationships (
            id serial PRIMARY KEY,
            source_ioc_id integer NOT NULL REFERENCES ioc(id),
            target_ioc_id integer NOT NULL REFERENCES ioc(id),
            relationship_type varchar NOT NULL,
            confidence integer DEFAULT 50,
            created_at timestamp without time zone DEFAULT now()
        )
        """))
        await conn.execute(text("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_ioc_graph_relationship
        ON ioc_graph_relationships(source_ioc_id, target_ioc_id, relationship_type)
        """))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ioc_graph_source ON ioc_graph_relationships(source_ioc_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ioc_graph_target ON ioc_graph_relationships(target_ioc_id)"))

        # Detection rules for behavioral detections.
        await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS detection_rules (
            id serial PRIMARY KEY,
            name varchar NOT NULL,
            description text DEFAULT '',
            rule_type varchar NOT NULL,
            severity varchar NOT NULL DEFAULT 'low',
            enabled boolean NOT NULL DEFAULT true,
            created_at timestamp without time zone DEFAULT now()
        )
        """))
        await conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_detection_rules_name ON detection_rules(name)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_detection_rules_rule_type ON detection_rules(rule_type)"))
        await conn.execute(text("""
        INSERT INTO detection_rules(name, description, rule_type, severity, enabled)
        VALUES
            ('Suspicious TLD', 'Domain uses risky top-level domain', 'suspicious_tld', 'medium', true),
            ('High Entropy Domain', 'Domain entropy suggests algorithmic generation', 'high_entropy_domain', 'high', true),
            ('Phishing Keyword Domain', 'Domain includes common phishing lure keywords', 'phishing_keyword_domain', 'medium', true),
            ('Homoglyph Domain', 'Domain looks like a homoglyph or punycode impersonation', 'homoglyph_domain', 'high', true)
        ON CONFLICT (name) DO NOTHING
        """))

        # Ensure IOC foreign key points to the canonical threat_actors table.
        await conn.execute(text("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = 'ioc' AND column_name = 'threat_actor_id'
            ) THEN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.table_constraints
                    WHERE table_name='ioc' AND constraint_name='ioc_threat_actor_id_fkey'
                ) THEN
                    ALTER TABLE ioc
                    ADD CONSTRAINT ioc_threat_actor_id_fkey
                    FOREIGN KEY (threat_actor_id) REFERENCES threat_actors(id);
                END IF;
            END IF;
        END $$;
        """))
        # create file_scans table if not exists
        await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS file_scans (
            id serial ,
            user_id integer NOT NULL references users(id),
            filename varchar NOT NULL,
            sha256 varchar NOT NULL,
            vt_score integer DEFAULT 0,
            risk_score integer DEFAULT 0,
            vt_raw_json jsonb DEFAULT '{}'::jsonb,
            status varchar DEFAULT 'pending',
            created_at timestamp without time zone DEFAULT now(),
            completed_at timestamp without time zone
        )
        """))
        # create events table if not exists
        await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS events (
            id serial PRIMARY KEY,
            user_id integer NOT NULL references users(id),
            alert_id integer references alerts(id),
            source varchar NOT NULL DEFAULT 'api',
            domain varchar,
            url varchar,
            ip varchar,
            file_hash varchar,
            raw_event jsonb DEFAULT '{}'::jsonb,
            event_type varchar NOT NULL DEFAULT 'generic',
            extracted_observables jsonb DEFAULT '{}'::jsonb,
            matched_iocs jsonb DEFAULT '{}'::jsonb,
            status varchar NOT NULL DEFAULT 'processed',
            created_at timestamp without time zone DEFAULT now()
        )
        """))
        # create alerts table if not exists
        await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS alerts (
            id serial PRIMARY KEY,
            fingerprint varchar,
            observable_type varchar,
            observable_value varchar,
            severity varchar NOT NULL DEFAULT 'low',
            title varchar NOT NULL,
            description text DEFAULT '',
            matched_count integer DEFAULT 0,
            status varchar NOT NULL DEFAULT 'open',
            first_seen_at timestamp without time zone DEFAULT now(),
            last_seen_at timestamp without time zone DEFAULT now(),
            occurrence_count integer DEFAULT 1,
            created_at timestamp without time zone DEFAULT now()
        )
        """))
        await conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS alert_id integer references alerts(id)"))
        await conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS domain varchar"))
        await conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS url varchar"))
        await conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS ip varchar"))
        await conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS file_hash varchar"))
        await conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS raw_event jsonb DEFAULT '{}'::jsonb"))
        await conn.execute(text("ALTER TABLE events ADD COLUMN IF NOT EXISTS raw_payload jsonb DEFAULT '{}'::jsonb"))
        await conn.execute(text("UPDATE events SET raw_event = COALESCE(raw_event, raw_payload, '{}'::jsonb)"))
        await conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS fingerprint varchar"))
        await conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS observable_type varchar"))
        await conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS observable_value varchar"))
        await conn.execute(text("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = 'alerts' AND column_name = 'event_id'
            ) THEN
                ALTER TABLE alerts ALTER COLUMN event_id DROP NOT NULL;
            END IF;
        END $$;
        """))
        await conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS first_seen_at timestamp without time zone DEFAULT now()"))
        await conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS last_seen_at timestamp without time zone DEFAULT now()"))
        await conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS occurrence_count integer DEFAULT 1"))
        await conn.execute(text("UPDATE alerts SET first_seen_at = COALESCE(first_seen_at, created_at, now())"))
        await conn.execute(text("UPDATE alerts SET last_seen_at = COALESCE(last_seen_at, created_at, now())"))
        await conn.execute(text("UPDATE alerts SET occurrence_count = COALESCE(occurrence_count, 1)"))
        await conn.execute(text("UPDATE alerts SET observable_type = COALESCE(observable_type, 'unknown')"))
        await conn.execute(text("UPDATE alerts SET observable_value = COALESCE(observable_value, 'unknown')"))
        await conn.execute(text("UPDATE alerts SET fingerprint = COALESCE(fingerprint, 'legacy-' || id::text)"))
        # add indexes separately
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_user_id ON scans(user_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scan_results_scan_id ON scan_results(scan_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_file_scans_sha256 ON file_scans(sha256)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ioc_value ON ioc(value)"))
        await conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS idx_ioc_unique_type_value ON ioc(type, value)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_user_id ON events(user_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_alert_id ON events(alert_id)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_domain ON events(domain)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_url ON events(url)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_ip ON events(ip)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_events_file_hash ON events(file_hash)"))
        await conn.execute(text("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_name = 'alerts' AND column_name = 'event_id'
            ) THEN
                CREATE INDEX IF NOT EXISTS ix_alerts_event_id ON alerts(event_id);
            END IF;
        END $$;
        """))
        await conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ux_alerts_fingerprint ON alerts(fingerprint)"))
        # Canonicalize legacy IOC type values.
        await conn.execute(text("""
        INSERT INTO ioc(type, value, threat_actor_id, source)
        SELECT 'file_hash', value, threat_actor_id, source
        FROM ioc
        WHERE type = 'hash'
        ON CONFLICT (type, value) DO NOTHING
        """))
        await conn.execute(text("DELETE FROM ioc WHERE type = 'hash'"))
        print("Schema updates applied.")

if __name__ == '__main__':
    asyncio.run(main())
